import Query
import Foundation
import PrivilegeModule
import NIOHTTP1
@preconcurrency import AnyCodable

extension PrivilegeSystem {
    /// 权限仲裁控制器。
    ///
    /// `Arbitrator` 会把一次鉴权请求拆成三类策略判断：
    /// 角色策略、用户/群组/父群组域策略，以及可选的资源权限策略。最终结果是所有
    /// 策略结果的逻辑 AND：任意一个策略返回 `false`，整体就会拒绝。
    ///
    /// ```swift
    /// let result = try await system.arbitrator.judge(
    ///     moduleId: module.moduleId,
    ///     user: user,
    ///     role: role,
    ///     resource: ["global": AnyCodable(true)],
    ///     operation: "manage_all",
    ///     privilegeIds: []
    /// )
    ///
    /// if result.result {
    ///     // 允许访问
    /// }
    /// ```
    ///
    /// - Important: 传入的 `role` 必须已经属于 `user`。它可以是用户直接角色、
    ///   用户所在群组的群组角色，或用户在某个群组内的组内角色。否则仲裁会在查询
    ///   OPA 策略前失败。
    public final class Arbitrator: SystemOPAController {
        package let db: PGDatabase
        package let eventLoop: EventLoop
        package let opa: OPA
        
        public let logger: Logger
        
        let roleController: RoleController
        
        init(
            db: PGDatabase,
            eventLoop: EventLoop,
            opa: OPA,
            roleController: RoleController,
            logger: Logger
        ) {
            self.db = db
            self.eventLoop = eventLoop
            self.opa = opa
            self.roleController = roleController
            self.logger = logger
        }
        
        /// 使用类型化资源执行权限仲裁。
        ///
        /// 该重载适合已经通过 `PrivilegeModule.ResourceController` 创建并查询到资源
        /// 的场景。资源的 JSON 内容会作为 `input.resource` 传给 OPA。
        ///
        /// ```swift
        /// let anyResource = AnyResource(fileResource)
        /// let result = try await system.arbitrator.judge(
        ///     moduleId: module.moduleId,
        ///     user: user,
        ///     role: role,
        ///     resource: anyResource,
        ///     operation: AnyOperation(op: FileOperation.read),
        ///     privilegeIds: [readPrivilege.id]
        /// )
        /// ```
        ///
        /// - Parameters:
        ///   - moduleId: 参与仲裁的业务模块 ID。
        ///   - user: 请求访问资源的用户。
        ///   - role: 本次访问选择使用的角色。
        ///   - resource: 类型擦除后的资源 DTO。
        ///   - operation: 本次访问的操作。
        ///   - privilegeIds: 需要额外参与判断的资源权限 ID。传空数组时只判断角色和域。
        ///
        /// - Returns: 包含最终布尔结果和每条策略报告的仲裁结果。
        /// - Throws: 当角色不属于用户、数据库数据收集失败或 OPA 查询失败时返回错误。
        public func judge(
            moduleId: UUID,
            user: QUser,
            role: QRole,
            resource: AnyResource,
            operation: AnyOperation,
            privilegeIds: OrderedSet<UUID>
        ) -> EventLoopRes<Result, Errcase> {
            let logger = getActionLogger()

            logger.info("执行 权限仲裁 操作", metadata: [
                "moduleId": .stringConvertible(moduleId.shortString),
                "user": .summaryData(user),
                "role": .summaryData(role),
                "operation": .summaryData(operation),
                "resource:": .summaryData(resource)
            ])
            logger.debug("操作参数", metadata: [
                "user": .data(user),
                "role": .data(role),
                "resource": .data(resource),
                "privilegeIds": .data(privilegeIds)
            ])
            
            // 检查所提供的 role 是否是 user 可用的身份，否则报错
            return roleController.is(role: role, appointedTo: user).flatMap {
                $0 ?
                self.db.eventLoop.makeSucceededResult(()) :
                self.db.eventLoop.makeFailedResult(Errcase.arbitrationDataCollectFailed, "所提供的身份并未被任命与用户", metadata: ["user": .data(user), "role": .data(role)], category: .external(suggestions: ["身份必须已任命与 \(user.email)"], userdata: .init(HTTPResponseStatus.forbidden)))
            }.flatMap {
                user.model(from: self.db).errCast(Errcase.arbitrationDataCollectFailed, "User 模型取得失败", category: .internal)
            }.flatMap { user in
                role.model(from: self.db).errCast(Errcase.arbitrationDataCollectFailed, "Role 模型取得失败", category: .internal).map {
                    (user, $0)
                }
            }.flatMap { user, role in
                self.__judge(
                    moduleId: moduleId,
                    user: user,
                    role: role,
                    resource: resource,
                    operation: operation,
                    privilegeIds: privilegeIds,
                    logger: logger
                )
            }.map { res in
                logger.info("权限仲裁 操作执行成功", metadata: ["result": .summaryData(res)])
                logger.debug("仲裁结果", metadata: ["result": .data(res)])
                return res
            }.logIfFail(logger: logger, metadata: [
                "user": .data(user),
                "role": .data(role),
                "resource": .data(resource),
                "privilegeIds": .data(privilegeIds)
            ])
        }
        
        /// 使用类型化资源执行权限仲裁。
        ///
        /// 该重载适合已经通过 `PrivilegeModule.ResourceController` 创建并查询到资源
        /// 的场景。资源的 JSON 内容会作为 `input.resource` 传给 OPA。
        ///
        /// ```swift
        /// let anyResource = AnyResource(fileResource)
        /// let result = try await system.arbitrator.judge(
        ///     moduleId: module.moduleId,
        ///     userId: userId,
        ///     roleId: roleId,
        ///     resource: anyResource,
        ///     operation: AnyOperation(op: FileOperation.read),
        ///     privilegeIds: [readPrivilege.id]
        /// )
        /// ```
        ///
        /// - Parameters:
        ///   - moduleId: 参与仲裁的业务模块 ID。
        ///   - userId: 请求访问资源的用户的 ID。
        ///   - roleId: 本次访问选择使用的角色的 ID。
        ///   - resource: 类型擦除后的资源 DTO。
        ///   - operation: 本次访问的操作。
        ///   - privilegeIds: 需要额外参与判断的资源权限 ID。传空数组时只判断角色和域。
        ///
        /// - Returns: 包含最终布尔结果和每条策略报告的仲裁结果。
        /// - Throws: 当角色不属于用户、数据库数据收集失败或 OPA 查询失败时返回错误。
        public func judge(
            moduleId: UUID,
            userId: UUID,
            roleId: UUID,
            resource: AnyResource,
            operation: AnyOperation,
            privilegeIds: OrderedSet<UUID>
        ) -> EventLoopRes<Result, Errcase> {
            let logger = getActionLogger()

            logger.info("执行 权限仲裁 操作", metadata: [
                "moduleId": .stringConvertible(moduleId.shortString),
                "userId": .summaryData(userId),
                "roleId": .summaryData(roleId),
                "operation": .summaryData(operation),
                "resource:": .summaryData(resource)
            ])
            logger.debug("操作参数", metadata: [
                "userId": .data(userId),
                "roleId": .data(roleId),
                "resource": .data(resource),
                "privilegeIds": .data(privilegeIds)
            ])
            
            // 检查所提供的 role 是否是 user 可用的身份，否则报错
            return roleController.is(roleId: roleId, appointedTo: userId).flatMap {
                $0 ?
                self.db.eventLoop.makeSucceededResult(()) :
                self.db.eventLoop.makeFailedResult(Errcase.arbitrationDataCollectFailed, "所提供的身份并未被任命与用户的", metadata: ["user_id": .data(userId), "role_id": .data(roleId)], category: .external(suggestions: ["身份必须已任命与该用户"], userdata: .init(HTTPResponseStatus.forbidden)))
            }.flatMap {
                // 从数据库中取得 User 模型
                __SDBM.User.query(on: self.db)
                    .filter(\.$id == userId)
                    .first()
                    .withError(Errcase.arbitrationDataCollectFailed, "取得 User 主模型失败", metadata: ["id": .stringConvertible(userId)], category: .internal)
                    .flatMap
                { user in
                    guard let u = user else {
                        return self.db.eventLoop.makeFailedResult(Errcase.arbitrationDataCollectFailed, "要仲裁的用户不存在", metadata: ["id": .stringConvertible(userId)], category: .external(suggestions: ["请提供有效的用户账号"], userdata: .init(HTTPResponseStatus.notFound)))
                    }
                    return self.db.eventLoop.makeSucceededResult(u)
                }
            }.flatMap { user in
                // 从数据库中取得 User 模型
                __SDBM.Role.query(on: self.db)
                    .filter(\.$id == roleId)
                    .first()
                    .withError(Errcase.arbitrationDataCollectFailed, "取得 Role 主模型失败", metadata: ["id": .stringConvertible(roleId)], category: .internal)
                    .flatMap
                { role in
                    guard let r = role else {
                        return self.db.eventLoop.makeFailedResult(Errcase.arbitrationDataCollectFailed, "要仲裁的用户角色不存在", metadata: ["id": .stringConvertible(roleId)], category: .external(suggestions: ["请提供有效的用户登陆角色身份"], userdata: .init(HTTPResponseStatus.notFound)))
                    }
                    return self.db.eventLoop.makeSucceededResult(r)
                }.map {
                    (user, $0)
                }
            }.flatMap { user, role in
                self.__judge(moduleId: moduleId, user: user, role: role, resource: resource, operation: operation, privilegeIds: privilegeIds, logger: logger)
            }.map { res in
                logger.info("权限仲裁 操作执行成功", metadata: ["result": .summaryData(res)])
                logger.debug("仲裁结果", metadata: ["result": .data(res)])
                return res
            }.logIfFail(logger: logger, metadata: [
                "userId": .data(userId),
                "roleId": .data(roleId),
                "resource": .data(resource),
                "privilegeIds": .data(privilegeIds)
            ])
        }
        
        func __judge(
            moduleId: UUID,
            user: __SDBM.User,
            role: __SDBM.Role,
            resource: AnyResource,
            operation: AnyOperation,
            privilegeIds: OrderedSet<UUID>,
            logger: Logger
        ) -> EventLoopRes<Result, Errcase> {
            
            let userGetter = db.eventLoop.submitResult { () throws(Errcase.ErrType) in
                let u = try required(throws: Errcase.arbitrationDataCollectFailed, "创建 User DTO 数据失败", category: .internal) {
                    try QUser.make(from: user).get()
                }
                
                let r = try required(throws: Errcase.arbitrationDataCollectFailed, "创建 Role DTO 数据失败", category: .internal) {
                    try QRole.make(from: role).get()
                }
                
                return (u, r)
            }
            
            // 查询用户所在的群组，父群组的所有域权限
            let groupDomainPolicies: EventLoopRes<[DomainData], Errcase> = userGetter.flatMap { userDTO, roleDTO in
                user.$groups.query(on: self.db)
                    .with(\.$supers) { path in
                        path.with(\.$ancestor)
                    }
                    .all()
                    .withError(Errcase.arbitrationDataCollectFailed, "取得用户所加入的所有群组失败", category: .internal)
                    .flatMapThrowing
                { (groups: [__SDBM.Group]) throws(Errcase.ErrType) in
                    let gsList = [__SDBM.Group]((
                        groups +
                        groups.flatMap { $0.supers.map { $0.ancestor } }
                    ).uniqued())

                    let gsDict: [UUID: __SDBM.Group] = try required(throws: Errcase.arbitrateFailed, "取得群组 ID 失败", category: .internal) {
                        try Dictionary(uniqueKeysWithValues: gsList.map { (try $0.requireID(), $0) })
                    }

                    return gsDict
                }.flatMap { (groups: [UUID: __SDBM.Group]) in
                    guard !groups.isEmpty else {
                        return self.db.eventLoop.makeSucceededResult([])
                    }
                    
                    return __SDBM.DomainPolicy.query(on: self.db)
                        .join(__SDBM.DomainGroupPivot.self, on: \__SDBM.DomainPolicy.$parent.$id == \__SDBM.DomainGroupPivot.$primaryModel.$id)
                        .filter(__SDBM.DomainGroupPivot.self, \.$secondaryModel.$id ~~ Array(groups.keys))
                        .field(\.$id)
                        .field(\.$parent.$id)
                        .field(__SDBM.DomainGroupPivot.self, \.$id)
                        .field(__SDBM.DomainGroupPivot.self, \.$primaryModel.$id)
                        .field(__SDBM.DomainGroupPivot.self, \.$secondaryModel.$id)
                        .all()
                        .withError(Errcase.arbitrationDataCollectFailed, "取得 Domain Pivot 数据失败", category: .internal)
                        .flatMapThrowing
                    { policies throws(Errcase.ErrType) in
                        try required(throws: Errcase.arbitrationDataCollectFailed, "取得 Domain 数据失败", category: .inherit) {
                            try policies.map { policy in
                                let pivot = try required(throws: Errcase.arbitrationDataCollectFailed, "取得 DomainGroupPivot 数据失败", category: .internal) {
                                    try policy.joined(__SDBM.DomainGroupPivot.self)
                                }
                                
                                // 从最开始传入的 groups 内存集合里，凭借 pivot 的 groupId 瞬间定位到完整的 __SDBM.Group 实体
                                guard let associatedGroup = groups[pivot.$secondaryModel.id] else {
                                    throw Errcase.arbitrationDataCollectFailed.d("群组数据映射丢失", category: .internal)
                                }
                                
                                return try required(throws: Errcase.arbitrationDataCollectFailed, "Domain 数据装配失败", category: .inherit) {
                                    try DomainData(
                                        domainId: policy.$parent.id,
                                        policyId: policy.requireID(),
                                        resource: resource.json,
                                        operation: operation.rawValue,
                                        user: userDTO,
                                        role: roleDTO,
                                        group: .make(from: associatedGroup).get()
                                    )
                                }
                            }
                        }
                    }
                }
            }
            
            // 查询用户本身被赋予的域权限
            let userDomainPolicies: EventLoopRes<[DomainData], Errcase> = userGetter.flatMap { userDTO, roleDTO in
                __SDBM.DomainPolicy.query(on: self.db)
                    .join(__SDBM.UserDomainPivot.self, on: \__SDBM.DomainPolicy.$parent.$id == \__SDBM.UserDomainPivot.$secondaryModel.$id)
                    .filter(__SDBM.UserDomainPivot.self, \.$primaryModel.$id == userDTO.id)
                    .field(\.$id)
                    .field(\.$parent.$id)
                    .unique()
                    .all()
                    .withError(Errcase.arbitrationDataCollectFailed, "数据库加载用户域权限失败", category: .internal)
                    .flatMapThrowing
                { policies throws(Errcase.ErrType) in
                    try required(throws: Errcase.arbitrationDataCollectFailed, "取得 Domain 数据失败", category: .internal) {
                        try policies.map { policy in
                            try DomainData(
                                domainId: policy.$parent.id,
                                policyId: policy.requireID(),
                                resource: resource.json,
                                operation: operation.rawValue,
                                user: userDTO,
                                role: roleDTO,
                                group: nil
                            )
                        }
                    }
                }
            }
            
            // 查询该用户所有的域权限，包括其所在的群组，父群组的所有域权限，及其本身被赋予的域权限
            return userGetter.flatMap { userDTO, roleDTO in
                [groupDomainPolicies, userDomainPolicies]
                    .flatten(on: self.db.eventLoop)
                    .flatMap
                { domainDatas in
                    __SDBM.RolePolicy.query(on: self.db)
                        .filter(\.$parent.$id == roleDTO.id)
                        .all()
                        .withError(Errcase.arbitrationDataCollectFailed, "从数据库中取得 Role 的 policy 列表失败", category: .inherit)
                        .flatMapThrowing
                    { rolePolicies throws(Errcase.ErrType) in
                        try required(throws: Errcase.arbitrationDataCollectFailed, "取得 Role 的 id 失败", category: .internal) {
                            try rolePolicies.map { try $0.requireID() }
                        }
                    }.flatMap { policyIds in
                        self.__judge(
                            input: ArbitrateData(
                                moduleId: moduleId,
                                domains: .init(domainDatas.flatMap { $0 }),
                                role: .init(
                                    policyIds: .init(policyIds),
                                    resource: resource.json,
                                    operation: operation.rawValue,
                                    user: userDTO,
                                    role: roleDTO
                                ),
                                privileges: privilegeIds.mapToSet {
                                    .init(
                                        privilegeId: $0,
                                        resource: resource.json,
                                        operation: operation.rawValue,
                                        user: userDTO,
                                        role: roleDTO
                                    )
                                }
                            ), logger: logger
                        )
                    }
                }
            }
        }
        
        func __judge(
            input: ArbitrateData,
            logger: Logger
        ) -> EventLoopRes<Result, Errcase> {
            // 取得用户身份的 policy
            let rolesAuth = input.role.policyIds.map { policyId in
                eventLoop.submitResult { () throws(Errcase.ErrType) in
                    let arbiId = UUID()
                    logger.debug("进行 Role 仲裁", metadata: ["role": .data(input.role), "arbitrate-id": .stringConvertible(arbiId)])
                    
                    let roleJson = try required(throws: Errcase.arbitrateFailed, "将角色数据转为 Json 失败", category: .internal) {
                        try input.role.wrappedJson()
                    }
                    
                    return (arbiId, roleJson)
                }.flatMap { (arbiId, json) in
                    self.opa.query.data(
                        from: "/rules" + policyPath(moduleId: input.moduleId, modelId: input.role.role.id, policyId: policyId, type: Role.self, format: .path) + "/allow",
                        input: json,
                        to: Bool.self
                    ).errCast(Errcase.arbitrateFailed, "OPA Query 用户身份 失败", category: .internal)
                    .map { res in
                        logger.debug("Role 仲裁结果", metadata: ["result": .data(res), "arbitrate-id": .stringConvertible(arbiId)])
                        return (Result.IdKey(type: .role, moduleId: input.moduleId, modelId: input.role.role.id, policyId: policyId), res)
                    }
                }
            }
            
            // 取得所有域权限的 policy
            let domainsAuth = input.domains.map { domainData in
                eventLoop.submitResult { () throws(Errcase.ErrType) in
                    let arbiId = UUID()
                    logger.debug("进行 Domain 仲裁", metadata: ["domain": .data(domainData), "arbitrate-id": .stringConvertible(arbiId)])
                    
                    let domainJson = try required(throws: Errcase.arbitrateFailed, "将域数据转为 Json 失败", category: .internal) {
                        try domainData.wrappedJson()
                    }
                    
                    return (arbiId, domainJson)
                }.flatMap { (arbiId, json) in
                    self.opa.query.data(
                        from: "/rules" + policyPath(moduleId: input.moduleId, modelId: domainData.domainId, policyId: domainData.policyId, type: Domain.self, format: .path) + "/allow",
                        input: json,
                        to: Bool.self
                    )
                    .errCast(Errcase.arbitrateFailed, "OPA Query 域权限 失败", category: .internal)
                    .map { res in
                        logger.debug("Domain 仲裁结果", metadata: ["result": .data(res), "arbitrate-id": .stringConvertible(arbiId)])
                        return (Result.IdKey(type: .domain, moduleId: input.moduleId, modelId: domainData.domainId, policyId: domainData.policyId), res)
                    }
                }
            }
            
            // 取得资源权限的 policy
            let privilegesAuth = input.privileges.map { privilegeData in
                eventLoop.submitResult { () throws(Errcase.ErrType) in
                    let arbiId = UUID()
                    logger.debug("进行 Privilege 仲裁", metadata: ["privilege": .data(privilegeData), "arbitrate-id": .stringConvertible(arbiId)])
                    
                    let privilegeJson = try required(throws: Errcase.arbitrateFailed, "将资源权限数据转为 Json 失败", category: .internal) {
                        try privilegeData.wrappedJson()
                    }
                    
                    return (arbiId, privilegeJson)
                }.flatMap { (arbiId, json) in
                    self.opa.query.data(
                        from: "/rules" + policyPath(moduleId: input.moduleId, modelId: nil, policyId: privilegeData.privilegeId, type: "privilege", format: .path) + "/allow",
                        input: json,
                        to: Bool.self
                    )
                    .errCast(Errcase.arbitrateFailed, "OPA Query 资源权限 失败", category: .internal)
                    .map { res in
                        logger.debug("Privilege 仲裁结果", metadata: ["result": .data(res), "arbitrate-id": .stringConvertible(arbiId)])
                        return (Result.IdKey(type: .privilege, moduleId: input.moduleId, modelId: nil, policyId: privilegeData.privilegeId), res)
                    }
                }
            }
            
            // 并行执行所有的权限判断
            return (
                rolesAuth +
                domainsAuth +
                privilegesAuth
            ).flatten(on: eventLoop).flatMap { (res: [(Result.IdKey, OPA.Answer<Bool?>)]) in
                guard res.count > 0 else { return self.eventLoop.makeSucceededResult(.init(result: false, reports: [:])) }
                var result = Result(result: true, reports: [:])
                for (k, r) in res {
                    guard let r = r.result else {
                        return self.eventLoop.makeFailedResult(Errcase.arbitrateFailed, "OPA 查询异常，Path 路径未找到", category: .internal)
                    }
                    result.and(result: r)
                    result.append(id: k, value: r)
                }
                return self.eventLoop.makeSucceededResult(result)
            }
        }
    }
}

extension PrivilegeSystem.Arbitrator {
    public func judge(
        moduleId: UUID,
        user: QUser,
        role: QRole,
        resource: GResource,
        operation: AnyOperation,
        privilegeIds: OrderedSet<UUID>
    ) -> EventLoopRes<Result, PrivilegeSystem.Errcase> {
        judge(
            moduleId: moduleId,
            user: user,
            role: role,
            resource: AnyResource(from: resource),
            operation: operation,
            privilegeIds: privilegeIds
        )
    }
    
    public func judge(
        moduleId: UUID,
        userId: UUID,
        roleId: UUID,
        resource: GResource,
        operation: AnyOperation,
        privilegeIds: OrderedSet<UUID>
    ) -> EventLoopRes<Result, PrivilegeSystem.Errcase> {
        judge(
            moduleId: moduleId,
            userId: userId,
            roleId: roleId,
            resource: AnyResource(from: resource),
            operation: operation,
            privilegeIds: privilegeIds
        )
    }
}

extension PrivilegeSystem.Arbitrator {
    /// 一次权限仲裁的结果。
    ///
    /// `result` 是所有策略报告经过 AND 之后的最终结果；`reports` 保留每条策略的
    /// 原始布尔结果，便于调试为什么某次访问被允许或拒绝。
    public struct Result: Sendable, CustomStringConvertible, Loggerable {
        /// 仲裁报告中一条策略结果的唯一键。
        public struct IdKey: Sendable, Hashable {
            /// 策略所属类别。
            public enum T: Sendable, Hashable {
                /// 角色策略。
                case role
                /// 域策略。
                case domain
                /// 资源权限策略。
                case privilege
            }
            /// 策略类别。
            public let type: T
            /// 策略所属模块 ID。
            public let moduleId: UUID
            /// role、domain 或 privilege 的 ID。
            public let modelId: UUID?
            /// 策略的 ID。
            public let policyId: UUID
            
            internal init(type: T, moduleId: UUID, modelId: UUID?, policyId: UUID) {
                self.type = type
                self.moduleId = moduleId
                self.modelId = modelId
                self.policyId = policyId
            }
        }
        
        /// 最终仲裁结果。
        public private(set) var result: Bool
        /// 每条 role/domain/privilege 策略的独立结果。
        public private(set) var reports: OrderedDictionary<IdKey, Bool>
        
        mutating func and(result: Bool) {
            self.result = self.result && result
        }
        
        mutating func append(id: IdKey, value: Bool) {
            self.reports[id] = value
        }
        
        public var description: String {
            __logDescription(summary: false)
        }
        
        public var summaryDescription: String {
            __logDescription(summary: true)
        }
        
        func __logDescription(summary: Bool) -> String {
            var res = ""
            
            for (k, v) in reports {
                let path = switch k.type {
                case .role: policyPath(moduleId: k.moduleId, modelId: k.modelId, policyId: k.policyId, type: Role.self, format: .path)
                case .domain: policyPath(moduleId: k.moduleId, modelId: k.modelId, policyId: k.policyId, type: Domain.self, format: .path)
                case .privilege: policyPath(moduleId: k.moduleId, modelId: k.modelId, policyId: k.policyId, type: "privilege", format: .path)
                }
                
                if summary {
                    res += "\(path): \(v) | "
                } else {
                    res += "- \(path): \(v)\n"
                }
            }
            
            if summary {
                res += "\(result)"
            } else {
                res += "----------------------\n"
                res += "\(result)\n"
            }
            
            return res
        }
    }
    
    struct ArbitrateData: Hashable, Encodable, Sendable, CustomStringConvertible, Loggerable, DateWrapperModel {
        let moduleId: UUID
        let domains: OrderedSet<DomainData>
        let role: RoleData
        let privileges: OrderedSet<PrivilegeData>
        
        var description: String {
            formatJson([
                "module_id": AnyCodable(moduleId),
                "domains": AnyCodable(domains),
                "role": AnyCodable(role),
                "privileges": AnyCodable(privileges)
            ])
        }
    }
    
    struct RoleData: Hashable, Encodable, Sendable, CustomStringConvertible, Loggerable, DateWrapperModel {
        let policyIds: OrderedSet<UUID>
        let resource: [String: AnyCodable]
        let operation: String
        let user: QUser
        let role: QRole
        
        var description: String {
            formatJson([
                "resource": AnyCodable(resource),
                "operation": AnyCodable(operation),
                "user": AnyCodable(user),
                "role": AnyCodable(role),
                "policy_ids": AnyCodable(policyIds)
            ])
        }
    }
    
    struct DomainData: Hashable, Encodable, Sendable, CustomStringConvertible, Loggerable, DateWrapperModel {
        let domainId: UUID
        let policyId: UUID
        let resource: [String: AnyCodable]
        let operation: String
        let user: QUser
        let role: QRole
        let group: QGroup?
        
        var description: String {
            formatJson([
                "domain_id": AnyCodable(domainId),
                "resource": AnyCodable(resource),
                "operation": AnyCodable(operation),
                "user": AnyCodable(user),
                "role": AnyCodable(role),
                "group": AnyCodable(group),
                "policy_id": AnyCodable(policyId)
            ])
        }
    }
    
    struct PrivilegeData: Hashable, Encodable, Sendable, CustomStringConvertible, Loggerable, DateWrapperModel {
        let privilegeId: UUID
        let resource: [String: AnyCodable]
        let operation: String
        let user: QUser
        let role: QRole
        
        var description: String {
            formatJson([
                "privilege_id": AnyCodable(privilegeId),
                "resource": AnyCodable(resource),
                "operation": AnyCodable(operation),
                "user": AnyCodable(user),
                "role": AnyCodable(role)
            ])
        }
    }
}
