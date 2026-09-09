import Vapor
import Foundation
import PrivilegeModuleExtended

extension PrivilegeSystem {
    /// 权限服务层，提供权限相关的业务接口，负责账号注册、登录、Token 鉴权和密码修改等。
    ///
    /// `AccountController` 是处理 `User` 和 `Token` 数据结构生命周期的核心控制器。
    /// 它封装了底层数据库交互、双层盐化哈希密码验证、以及对称加密令牌机制，提供安全的无状态凭据验证。
    ///
    /// ### 账号注册
    /// 通过传入含有电子邮箱和一次性哈希密码（如 SHA256 等客户端完成的一次哈希）的 `PUser`，
    /// 可进行账号注册。控制器会自动在数据库中生成专有随机盐值并执行第二次哈希，从而落库：
    ///
    /// ```swift
    /// let userAuth = try await system.account.register(
    ///     email: "hello@example.com",
    ///     password: "hashedPasswordFromClient"
    /// )
    /// print("Registered user ID: \(userAuth.user.id)")
    /// ```
    ///
    /// ### 登录与鉴权
    /// 鉴权机制以令牌（Token）为核心，基于生成对称加密密钥（Crypto.Symm.Key）完成：
    ///
    /// ```swift
    /// // 登录并获取 Token 凭证
    /// let loginRes = try await system.account.login(by: userDto)
    /// let tokenStr = loginRes.token.tokenEncrypted // 包含验证信息的加密密文
    ///
    /// // 后续基于 tokenStr 发起请求鉴权
    /// let authKey = try await system.account.authenticate(token: receivedTokenDTO)
    /// ```
    public final class AccountController: SystemController, @unchecked Sendable {
        package let db: PGDatabase
        package let eventLoop: EventLoop
        package var nobodyRoleId: UUID? {
            get {
                lock.withLock { __nobodyRoleId }
            }
            set {
                lock.withLock { __nobodyRoleId = newValue }
            }
        }
        
        private let lock = NIOLock()
        private var __nobodyRoleId: UUID?
        
        let roleController: RoleController
        
        /// 操作记录日志器。
        public let logger: Logger
        
        init(
            db: PGDatabase,
            eventLoop: EventLoop,
            roleController: RoleController,
            logger: Logger
        ) {
            self.db = db
            self.eventLoop = eventLoop
            self.roleController = roleController
            self.logger = logger
            self.__nobodyRoleId = nil
        }
        
        /// 注册一个新账户，并将账户数据保存到数据库中。
        ///
        /// 注册接口会针对 `password` 字段（假设为已哈希的明文或直接明文）进行加盐（Salt）和双重哈希处理。
        ///
        /// - Parameter user: 用于注册的 `PUser` 准备对象，须包含有效的邮箱与基础密码数据。
        /// - Returns: 一个包裹在事件循环中的 `EventLoopRes` 结果，执行成功将返回注册完毕的 `QUser`。
        ///
        /// ```swift
        /// let dto = try PUser(email: "a@a.com", password: "pwd")
        /// let userQuery = try await system.account.register(for: dto).get()
        /// print("成功注册！", userQuery.id)
        /// ```
        public func register(
            for user: PUser,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<QUser, Errcase> {
            let logger = getActionLogger()
            
            logger.info("执行 账号注册 操作", metadata: ["user": .summaryData(user)])
            logger.debug("操作参数", metadata: ["user": .data(user)])
            
            let db = transactor?.db ?? self.db
            
            return db.trans(throws: .userRegisterFailed, "数据库事务执行失败", category: .internal) { db in
                guard let nobodyRoleId = self.nobodyRoleId else {
                    return db.eventLoop.makeFailedResult(Errcase.userRegisterFailed, "未找到 nobody 角色", category: .internal)
                }
                
                return __SDBM.User.query(on: db)
                    .filter(\.$email == user.email)
                    .count()
                    .withError(Errcase.userRegisterFailed, "查询用户是否存在时失败", category: .internal)
                    .flatMapThrowing
                { count throws(Errcase.ErrType) in
                    guard count == 0 else {
                        throw Errcase.userRegisterFailed.d("要注册的用户已存在", category: .external(userdata: .init(HTTPResponseStatus.conflict))).metadata(["user": .data(user)])
                    }
                }.flatMapThrowing { () throws(Errcase.ErrType) -> __SDBM.User in
                    try required(throws: Errcase.userRegisterFailed, "创建 User 模型失败", category: .inherit) {
                        try user.raw().get()
                    }
                }.flatMap { user in
                    user.save(on: db)
                        .withError(Errcase.userRegisterFailed, "将用户存入数据库时失败", category: .internal)
                        .map { user.id }
                }.flatMap { id in
                    __SDBM.User.find(id, on: db)
                        .withError(Errcase.userRegisterFailed, "重新加载用户失败", category: .internal)
                        .flatMapThrowing
                    { res throws(Errcase.ErrType) in
                        guard let user = res else {
                            throw .init(.userRegisterFailed, "用户未保存在数据库中，未知错误", category: .internal)
                        }
                        return try required(throws: Errcase.userRegisterFailed, "用户 DTO 生成失败", category: .internal) {
                            try required(throws: Errcase.userRegisterFailed, category: .internal) {
                                try QUser.make(from: user).get()
                            }
                        }
                    }
                }.flatMap { (user: QUser) in
                    self.roleController.appoint(on: .init(db: db), roleToUser: {
                        OrderedSet([nobodyRoleId]) => OrderedSet([user.id])
                    })
                    .errCast(Errcase.userRegisterFailed, "赋予用户 nobody 角色失败", category: .inherit)
                    .map { user }
                }.map {
                    logger.info("账号注册 操作执行成功")
                    return $0
                }
            }.logIfFail(logger: logger, metadata: ["user": .data(user)])
        }
        
        /// 验证用户凭据并登录，系统将为其生成并返回令牌认证 DTO。
        ///
        /// 该方法使用用户的密码和邮箱数据，如果数据库验证一致，则该账户下所有以前活动的登录 Token 都将被删除，
        /// 重新为其生成一个新的凭证与加密对称密钥（Token）。
        ///
        /// - Parameter userData: 具有登录必要数据（如密码与邮箱）的用户对象。
        /// - Returns: 返回经过授权生成的鉴权 `QToken` 数据。
        ///
        /// ```swift
        /// let loginDto = try PUser(email: "test@domain.com", password: "pwd")
        /// let token = try await system.account.login(by: loginDto).get()
        /// print("登录完成，Token的加密体为: \(token.tokenEncrypted)")
        /// ```
        public func login(
            by userData: PUser,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<QToken, Errcase> {
            let logger = getActionLogger()
            
            logger.info("执行 账号登录 操作", metadata: ["user": .summaryData(userData)])
            logger.debug("操作参数", metadata: ["user": .data(userData)])
            
            let db = transactor?.db ?? self.db
            
            return db.trans(throws: .userLoginFailed, "数据库事务执行失败", category: .internal) { db in
                __SDBM.User.query(on: db)
                    .filter(\.$email == userData.email)
                    .first()
                    .withError(Errcase.userLoginFailed, "从数据库中查询用户失败", category: .internal)
                    .flatMapThrowing
                { (res) throws(Errcase.ErrType) -> (__SDBM.User, UUID, __SDBM.Token) in
                    guard let user = res else {
                        throw Errcase.userLoginFailed.d("用户不存在", category: .external(suggestions: ["请先进行注册"], userdata: .init(HTTPResponseStatus.unauthorized)))
                    }
                    
                    guard
                        try required(throws: Errcase.userLoginFailed, "密码验证失败", category: .inherit, {
                            try user.verify(password: userData.hashedPassword)
                        })
                    else {
                        throw Errcase.userLoginFailed.d("用户密码不正确", category: .external(suggestions: ["请提供正确的账号密码"], userdata: .init(HTTPResponseStatus.unauthorized)))
                    }
                    
                    let userId = try required(throws: Errcase.userLoginFailed, "获取用户 ID 失败", category: .internal) {
                        try user.requireID()
                    }
                    
                    return (user, userId, PToken(for: userId).raw())
                }.flatMap { (user: __SDBM.User, id: UUID, token: __SDBM.Token) in
                    // 删除原有的 token (若有)
                    __SDBM.Token.query(on: db).filter(\.$user.$id == id).delete()
                        .withError(Errcase.userLoginFailed, "删除用户已存在的 token 时失败", metadata: ["user": .data(userData)], category: .internal)
                        .map { (user, id, token) }
                }.flatMap { (user, id, token) in
                    token.save(on: db)
                        .withError(Errcase.userLoginFailed, "用户 Token 写入数据库失败", metadata: ["user": .data(userData), "token": .data(token.id)], category: .internal)
                        .flatMapThrowing
                    { () throws(Errcase.ErrType) in
                        try required(throws: Errcase.userLoginFailed, category: .internal) {
                            try .make(from: token).get()
                        }
                    }
                }.map {
                    logger.info("账号登录 操作执行成功", metadata: ["user": .string(userData.email)])
                    return $0
                }
            }.logIfFail(logger: logger, metadata: ["user": .data(userData)])
        }

        /// 对传入的 Token 发起鉴权并还原为加密用对称密钥。
        ///
        /// 接收请求上下文中提供的 Token 令牌。如果令牌格式合法、在有效期内且在数据库内验证一致，将还原为一个对称密钥。
        ///
        /// - Parameter token: 构建自外部的 `PToken`。
        /// - Returns: 若鉴权成功，将返回可供解密使用的 `Crypto.Symm.Key` 对称密钥。
        ///
        /// ```swift
        /// // 假装请求中的 header 里拿到 token 字符串
        /// let reqTokenString = req.headers["Authorization"].first!
        /// let tokenDto = PToken(tokenString: reqTokenString)
        /// let key = try await system.account.authenticate(token: tokenDto).get()
        /// ```
        public func authenticate(
            token: EncryptedToken,
            roleId: UUID,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<AuthData, Errcase> {
            let logger = getActionLogger()
            
            logger.info("执行 Token 鉴权 操作", metadata: ["token": .summaryData(token)])
            logger.debug("操作参数", metadata: ["token": .data(token)])
            
            let db = transactor?.db ?? self.db
            
            return db.trans(throws: .userAuthenticateFailed, "数据库事务执行失败", category: .internal) { db in
                QRole.query(on: db)
                    .filter(\.id == roleId)
                    .first()
                    .errCast(Errcase.userAuthenticateFailed, "从数据库中获取角色信息失败", category: .internal)
                    .flatMap
                { r -> EventLoopResult<QRole, BasicError<PrivilegeSystem.Errcase>> in
                    guard let role = r else {
                        return db.eventLoop.makeFailedResult(Errcase.userAuthenticateFailed, "角色不存在", category: .external(suggestions: ["请提供正确的角色"], userdata: .init(HTTPResponseStatus.unauthorized)))
                    }
                    return db.eventLoop.makeSucceededResult(role)
                }.flatMap { role in
                    let tokenGetter: EventLoopRes<QToken, PrivilegeSystem.Errcase> = db.eventLoop.submitResult { () throws(Errcase.ErrType) in
                        guard token.tokenEncrypted.count == 124 else {
                            throw .init(.userAuthenticateFailed, "用户口令长度不正确，预期为 124 bytes", category: .external()).metadata(["count": .stringConvertible(token.tokenEncrypted.count)])
                        }
                    }.flatMap {
                        QToken.query(on: db)
                            .filter(\.credential == token.credential)
                            .first()
                            .errCast(Errcase.userAuthenticateFailed, "从数据库中获取用户凭据失败", category: .internal)
                    }.flatMapThrowing { token throws(Errcase.ErrType) in
                        guard let t = token else {
                            throw .init(.userAuthenticateFailed, "用户凭据不存在", category: .external(suggestions: ["请先进行登陆"], userdata: .init(HTTPResponseStatus.unauthorized)))
                        }
                        return t
                    }.flatMap { (t: QToken) in
                        t.$user.get(on: .init(db: db))
                            .errCast(Errcase.userAuthenticateFailed, "从数据库拉取 Token 关联用户失败", category: .inherit)
                            .flatMap
                        { user in
                            self.roleController.is(role: role, appointedTo: user, on: .init(db: db))
                                .errCast(Errcase.userAuthenticateFailed, "判断角色归属失败", category: .inherit)
                                .flatMap
                            { result in
                                guard result else {
                                    return db.eventLoop.makeFailedResult(Errcase.userAuthenticateFailed.d("所声明的角色(role_id)并未任命给该用户", category: .external(userdata: .init(HTTPResponseStatus.unauthorized))).metadata(["role_id": .stringConvertible(role.id), "user_email": .stringConvertible(user.email)]))
                                }
                                return db.eventLoop.makeSucceededResult(t)
                            }
                        }
                    }
                    
                    // 检查口令是否正确
                    return tokenGetter.flatMapThrowing { qToken throws(Errcase.ErrType) in
                        let key = try required(throws: Errcase.userAuthenticateFailed, "口令认证失败", category: .external(suggestions: ["请提供正确的登陆口令"], userdata: .init(HTTPResponseStatus.unauthorized))) {
                            try qToken.verify(encryptedToken: token.tokenEncrypted)
                        }
                        
                        return (SendableSymmKey(key: key), qToken)
                    }.flatMap{ (key: SendableSymmKey, token: QToken) in
                        token.$user.load(on: db)
                            .errCast(Errcase.userAuthenticateFailed, "从数据库中读取 User 模型失败", category: .internal)
                            .flatMap {
                                token.user.$info.load(on: db)
                                    .errCast(Errcase.userAuthenticateFailed, "从数据库中读取 User Info 模型失败", category: .internal)
                            }
                            .map { AuthData(key: key, token: token, role: role) }
                    }.map {
                        logger.info("Token 鉴权 操作执行成功")
                        return $0
                    }
                }
            }.logIfFail(logger: logger, metadata: ["token": .data(token)])
        }
        
        /// 为已知用户修改密码（以 Data 格式提供新哈希）。
        ///
        /// 用户的现有凭据 `userData` 中必须包含正确的旧密码哈希。
        /// 密码替换将触发重新生成盐值的操作。
        ///
        /// - Parameters:
        ///   - userData: `DTO.User` 实例，提供用户的电子邮箱及**当前正确的哈希密码**。
        ///   - hashedPassword: Data 格式的新的哈希密码流。
        /// - Returns: `QUser` 用户新的查询对象。
        public func changePassword(
            for userData: PUser,
            to hashedPassword: Data,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<QUser, Errcase> {
            changePassword(for: userData, to: hashedPassword.base64EncodedString(), on: transactor)
        }
        
        /// 为已知用户修改密码（以 String 格式提供新哈希）。
        ///
        /// 用户的现有凭据 `userData` 中必须包含正确的旧密码哈希。验证通过后，
        /// 系统将为新密码 `hashedPassword` 生成全新的随机盐值并覆盖记录。
        ///
        /// - Parameters:
        ///   - userData: `DTO.User` 实例，提供用户的电子邮箱及**当前正确的哈希密码**。
        ///   - hashedPassword: Base64 或其他格式编码的新字符串哈希密码。
        /// - Returns: `QUser` 密码已更改的查询对象。
        ///
        /// ```swift
        /// let newUserData = try await system.account.changePassword(
        ///     for: oldUserDto,
        ///     to: "brandNewHashedPwdStr"
        /// ).get()
        /// ```
        public func changePassword(
            for userData: PUser,
            to hashedPassword: String,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<QUser, Errcase> {
            let logger = getActionLogger()
            
            logger.info("执行 修改密码 操作", metadata: ["user": .summaryData(userData)])
            logger.debug("操作参数", metadata: ["token": .data(userData), "new_hashed_length": .stringConvertible(hashedPassword.count)])
            
            let db = transactor?.db ?? self.db
            
            return db.trans(throws: .userPasswordChangeFailed, "数据库事务执行失败", category: .internal) { db in
                __SDBM.User.query(on: db)
                    .filter(\.$email == userData.email)
                    .first()
                    .withError(Errcase.userPasswordChangeFailed, "从数据库中查询用户失败", category: .internal)
                    .flatMapThrowing
                { res throws(Errcase.ErrType) in
                    guard let user = res else {
                        throw Errcase.userPasswordChangeFailed.d("用户不存在", category: .external(suggestions: ["请先进行注册"], userdata: .init(HTTPResponseStatus.unauthorized)))
                    }
                    
                    guard (
                        try required(throws: Errcase.userPasswordChangeFailed, "用户密码认证失败", category: .internal) {
                            try user.verify(password: userData.hashedPassword)
                        } == true
                    ) else {
                        throw Errcase.userPasswordChangeFailed.d("用户密码不正确", category: .external(suggestions: ["请提供正确的密码"], userdata: .init(HTTPResponseStatus.unauthorized)))
                    }
                    
                    return user
                }.flatMap {
                    self.__changePassword(on: db, for: $0, to: hashedPassword)
                }.map {
                    logger.info("修改密码 操作执行成功")
                    return $0
                }
            }.logIfFail(logger: logger, metadata: ["token": .data(userData), "new_hashed_length": .stringConvertible(hashedPassword.count)])
        }
        
        public func changePassword(
            for userData: QUser,
            to hashedPassword: String,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<QUser, Errcase> {
            let logger = getActionLogger()
            
            logger.info("执行 修改密码 操作", metadata: ["user": .summaryData(userData)])
            logger.debug("操作参数", metadata: ["token": .data(userData), "new_hashed_length": .stringConvertible(hashedPassword.count)])
            
            let db = transactor?.db ?? self.db
            
            return db.trans(throws: .userPasswordChangeFailed, "数据库事务执行失败", category: .internal) { db in
                userData.model(from: db)
                    .errCast(Errcase.userPasswordChangeFailed, "从数据库中查询用户失败", category: .internal)
                    .flatMap
                {
                    self.__changePassword(on: db, for: $0, to: hashedPassword)
                }.map {
                    logger.info("修改密码 操作执行成功")
                    return $0
                }
            }.logIfFail(logger: logger, metadata: ["token": .data(userData), "new_hashed_length": .stringConvertible(hashedPassword.count)])
        }
        
        func __changePassword(
            on db: PGDatabase,
            for user: __SDBM.User,
            to hashedPassword: String
        ) -> EventLoopRes<QUser, Errcase> {
            db.eventLoop.bridge { () throws(Errcase.ErrType) in
                (user.salt, user.hashedPassword) = try required(throws: Errcase.userPasswordChangeFailed, "双重加密密码时失败", category: .internal) {
                    try PUser.doubleEncode(hashedPassword: hashedPassword).get()
                }
                
                return user
            }.flatMap { (user: __SDBM.User) -> EventLoopRes<__SDBM.User, Errcase> in
                return user
                    .update(on: db)
                    .withError(Errcase.userPasswordChangeFailed, "更新用户密码时失败", category: .internal)
                    .map { user }
            }.flatMapThrowing { user throws(Errcase.ErrType) in
                try required(throws: Errcase.userPasswordChangeFailed, category: .internal) {
                    try .make(from: user).get()
                }
            }
        }
    }
}
