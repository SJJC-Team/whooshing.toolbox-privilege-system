import OPA
import Foundation
import NIOHTTP1

public extension PrivilegeModule {
    /// 资源权限控制器，负责对当前模块下的资源操作许可（Privilege）进行定义、维护、以及向 OPA 下发策略规则。
    ///
    /// 这里的“资源权限”代表着某种具体操作或行为规范的策略脚本，例如：允许只有文档的所有者才能删除文档。
    /// 可以将它通过 `attach` 和 `detach` 分配给一个或多个 `Resource`。当角色试图访问资源时，系统将一并提取角色策略和资源策略，
    /// 交由 OPA 仲裁决定放行还是拒绝。
    ///
    /// - `create` / `createWithReturning`: 注册新的权限与底层 Rego 策略脚本。
    /// - `update`: 更新权限的元数据或修正底层 Rego 策略脚本。
    /// - `delete`: 废除并从系统中清除一项权限。
    /// - `attach` / `detach`: 将一项策略绑定至指定的系统资源实体，或者解除绑定。
    final class PrivilegeController: OPAController {
        package typealias E = Errcase
        
        package let db: PGDatabase
        package let eventLoop: EventLoop
        package let opa: OPA
        
        /// 模块内部的唯一标识 UUID
        let moduleId: UUID
        
        /// 操作记录日志器。
        public let logger: Logger
        
        public typealias S = PM<ResourceList>
        
        init(
            db: PGDatabase,
            opa: OPA,
            moduleId: UUID,
            eventLoop: EventLoop,
            logger: Logger
        ) {
            self.db = db
            self.eventLoop = eventLoop
            self.opa = opa
            self.moduleId = moduleId
            self.logger = logger
        }
        
        /// 创建并向系统和 OPA 同步一组资源权限（无返回数据版）。
        ///
        /// 适合用于应用初始化时的静默数据装配场景。
        ///
        /// - Parameter privileges: 一组预备状态的资源权限 DTO 集合。
        /// - Returns: `EventLoopRes<Void, Errcase>`
        public func create(
            privileges: OrderedSet<PPrivilege>,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<Void, Errcase> {
            let logger = getActionLogger()
            logger.info("执行 创建资源权限 操作", metadata: ["privileges": .summaryData(privileges)])
            logger.debug("操作参数", metadata: ["privileges": .data(privileges)])
            let db = transactor?.db ?? self.db
            // Pr: PPrivilege
            // P == Pr
            // M: PM<ResourceList>.Privilege
            // PT: Privilege
            return __createPolicy(
                on: db,
                relations: privileges,              // 资源策略创建无需绑定关系，传入策略列表
                policyType: __DBM.Privilege.self,
                label: "资源权限",
                errThrowing: .privilegeCreateFailed,
                policies: { [$0] },                 // 返回本地，即 Pr == P
                moduleId: { _ in moduleId },        // 服务模块 id 为本模块的 id
                policyKey: \.policy,
                modelId: { _, p in p.id! },         // 资源策略无绑定关系，使用本身的策略 id 作为 modelId
                policyIdSetter: { $0.set(id: $1) },
                modelBuilder: { p, mid in
                    let raw = p.raw()
                    raw.id = mid                    // 资源策略 fluent 模型的 id 必须指定，否则 fluent 会随机创建
                    return raw
                },
                opaPathHaveModelId: false
            )
            .map { _ in logger.info("创建资源权限 操作成功") }
        }
        
        /// 创建并向系统和 OPA 同步一组资源权限，且返回创建成功后的完整对象。
        ///
        /// 创建时自动为策略分配随机生成的 UUID，成功落库并同步到 OPA 后，可以取得查询状态（`DTO.Queried`）的权限对象。
        /// 只有取得分配过 ID 的 `QPrivilege`，后续才可以用于与资源的关联绑定（`attach`）。
        ///
        /// - Parameter privileges: 一组预备状态的资源权限 DTO 集合。
        /// - Returns: 已成功保存到数据库中并下发给 OPA 的权限 DTO 列表。
        public func createWithReturning(
            privileges: OrderedSet<PPrivilege>,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<[QPrivilege], Errcase> {
            let logger = getActionLogger()
            logger.info("执行 创建资源权限（返回） 操作", metadata: ["privileges": .summaryData(privileges)])
            logger.debug("操作参数", metadata: ["privileges": .data(privileges)])
            let db = transactor?.db ?? self.db
            return __createPolicy(
                on: db,
                relations: privileges,
                policyType: __DBM.Privilege.self,
                label: "资源权限",
                errThrowing: .privilegeCreateFailed,
                policies: { [$0] },
                moduleId: { _ in moduleId } ,
                policyKey: \.policy,
                modelId: { _, p in p.id! },
                policyIdSetter: { $0.set(id: $1) },
                modelBuilder: { p, mid in
                    let raw = p.raw()
                    raw.id = mid
                    return raw
                },
                opaPathHaveModelId: false
            ).flatMapThrowing { ps throws(Errcase.ErrType) in
                try required(throws: Errcase.privilegeCreateFailed, "Returning 解包失败", category: .internal) {
                    try ps.map { p in
                        try QPrivilege.make(from: p.fill()).get()
                    }
                }
            }
            .map { 
                logger.info("创建资源权限（返回） 操作成功", metadata: ["data": .summaryData($0)])
                logger.debug("创建资源权限（返回） 结果详细数据", metadata: ["data": .data($0)])
                return $0 
            }
        }
        
        /// 将某项具体的策略从系统与 OPA 中连根拔起。
        ///
        /// 一旦从系统抹除，曾经附加于资源上的此项策略关系也将失效和级联被删除，影响面较大。
        /// 
        /// - Parameter policy: 处于已查询状态的目标策略 `QPrivilege`。
        /// - Returns: `EventLoopRes<Void, Errcase>`
        public func delete(
            policy: QPrivilege,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<Void, Errcase> {
            let logger = getActionLogger()
            logger.info("执行 删除资源权限 操作", metadata: ["privilegeId": .stringConvertible(policy.id)])
            let db = transactor?.db ?? self.db
            return __deletePolicy(
                on: db,
                policy: policy,
                policyType: __DBM.Privilege.self,
                label: "资源权限",
                errThrowing: .privilegeDeleteFailed,
                filterBuilder: {
                    __DBM.Privilege
                        .query(on: $0)
                        .filter(\.$id == policy.id)
                },
                moduleId: { _ in moduleId },
                policyId: { $0.id },
                modelIdKey: \.id,
                opaPathHaveModelId: false
            )
            .map { _ in logger.info("删除资源权限 操作成功") }
        }
        
        /// 更新一项权限的信息与策略内容。
        ///
        /// 使用事务确保安全：优先同步执行数据库数据更新，一旦 OPA 返回同步错误，则立即撤回对本地数据库的改动，
        /// 防止 OPA 数据集与本地状态割裂。
        ///
        /// - Parameter updater: `PPrivilege.Updater` 更新执行器。
        /// - Returns: `EventLoopRes<QPrivilege, Errcase>` 更新完成的新对象。
        public func update(
            with updater: PPrivilege.Updater,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<QPrivilege, Errcase> {
            let logger = getActionLogger()
            logger.info("执行 更新资源权限 操作", metadata: ["data": .summaryData(updater)])
            logger.debug("更新资源权限 详细请求数据", metadata: ["data": .data(updater)])
            
            guard updater.updates.count > 0 else {
                return db.eventLoop.makeFailedResult(Errcase.privilegeUpdateFailed, "没有任何数据需要更新", category: .external(userdata: .init(HTTPResponseStatus.unprocessableEntity)))
            }
            
            let db = transactor?.db ?? self.db
            
            // 在 SQL 事务中，先执行 SQL 更新，保持该事务会话
            // 只有当 OPA 也更新成功后才提交事务
            // 否则，无论 SQL 或 OPA 更新失败，数据库会进行回滚
            // 而 OPA 无需进行回滚，因为仅处理一条策略数据，
            // 更新失败意味着其仍保留原数据在 OPA 中
            return db.trans(throws: Errcase.privilegeUpdateFailed, "数据库事务执行失败", category: .internal) { db in
                // 先将字段更新到数据库中: name, summary, policy
                self.__update(
                    on: db,
                    updater: updater,
                    label: "资源权限",
                    errThrowing: .privilegeUpdateFailed,
                    filterBuilder: { $0.filter(\.$id == updater.privilegeId) },
                    dtoBuilder: { QPrivilege.make(from: $0) }
                ).flatMap { updateRes in
                    guard let policyUpdater = updater.policyUpdate else {
                        return self.eventLoop.makeSucceededResult(updateRes)
                    }
                    
                    // 对策略进行修改，如果授意如此的话
                    // 如果此处策略修改失败，抛出错误导致数据库事务失败
                    // 则数据库也会回滚，而 OPA 无需进行回滚
                    // 更新失败意味着其仍保留原数据在 OPA 中
                    // 保证了数据库与 OPA 数据完全同步
                    let policy: String
                    do {
                        policy = try policyUpdater(updater.needsPeek ? updateRes : nil)
                    } catch {
                        return self.eventLoop.makeFailedResult(Errcase.privilegeUpdateFailed, "要更新的 Policy 出错", category: .external(userdata: .init(HTTPResponseStatus.unprocessableEntity)))
                    }
                    
                    let path = policyPath(
                        moduleId: self.moduleId,
                        modelId: nil,
                        policyId: updater.privilegeId,
                        type: __DBM.Privilege.self,
                        format: .route
                    )
                    
                    let fullPolicy = assemblePolicy(path: path, policy: policy)
                    
                    return self.opa.policy.save(by: path, content: fullPolicy)
                        .errCast(Errcase.privilegeUpdateFailed, "资源权限策略 OPA 更新失败", category: .internal)
                        .map { _ in updateRes }
                }
            }.map { 
                logger.info("更新资源权限 操作成功", metadata: ["data": .summaryData($0)])
                logger.debug("更新资源权限 结果详细数据", metadata: ["data": .data($0)])
                return $0 
            }
        }
    }
}

public extension PrivilegeModule.PrivilegeController {
    typealias Errcase = S.Errcase
    
    // MARK: - 资源权限附加
    
    /// 将多个权限绑定至多个资源（使用链式构造器模式）。
    ///
    /// 附加权限动作要求资源与权限都必须已存在于数据库中，任一不存在都会导致失败。
    /// 只有在成功执行绑定后，基于对应资源的请求鉴权才会经过这些权限策略的验证。
    ///
    /// - Parameter content: `@MTMRelationBuilder` 提供用于建立关系的 DSL 闭包。
    /// - Returns: `EventLoopRes<Void, S.Errcase>`
    func attach(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<UUID, UUID>
        privilegeToResource content: @Sendable @escaping () -> OrderedSet<MTMRelation<UUID, UUID>>
    ) -> EventLoopRes<Void, S.Errcase> {
        attach(privilegeToResource: content(), on: transactor)
    }
    
    /// 将多个权限绑定至多个资源（使用链式构造器模式）。
    ///
    /// 附加权限动作要求资源与权限都必须已存在于数据库中，任一不存在都会导致失败。
    /// 只有在成功执行绑定后，基于对应资源的请求鉴权才会经过这些权限策略的验证。
    ///
    /// - Parameter content: `@MTMRelationBuilder` 提供用于建立关系的 DSL 闭包。
    /// - Returns: `EventLoopRes<Void, S.Errcase>`
    func attach(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<S.QPrivilege, GResource>
        _ content: @Sendable @escaping () -> OrderedSet<MTMRelation<S.QPrivilege, GResource>>
    ) -> EventLoopRes<Void, S.Errcase> {
        attach(relations: content(), on: transactor)
    }
    
    // MARK: - 资源权限解除
    
    /// 将多个权限从多个资源上解绑（使用链式构造器模式）。
    ///
    /// 解除权限动作会使特定资源不再受到指定的策略脚本约束。
    /// 解除绑定时，权限对象必须通过数据库拉取，但被操作的资源可直接实例化 `AnyResource` 包装体并赋 UUID。
    ///
    /// - Parameter content: `@MTMRelationBuilder` 提供用于解绑关系的 DSL 闭包。
    /// - Returns: `EventLoopRes<Void, S.Errcase>`
    func detach(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<UUID, UUID>
        privilegeFromResource content: @Sendable @escaping () -> OrderedSet<MTMRelation<UUID, UUID>>
    ) -> EventLoopRes<Void, S.Errcase>  {
        detach(privilegeFromResource: content(), on: transactor)
    }
    
    /// 将多个权限从多个资源上解绑（使用链式构造器模式）。
    ///
    /// 解除权限动作会使特定资源不再受到指定的策略脚本约束。
    /// 解除绑定时，权限对象必须通过数据库拉取，但被操作的资源可直接实例化 `AnyResource` 包装体并赋 UUID。
    ///
    /// - Parameter content: `@MTMRelationBuilder` 提供用于解绑关系的 DSL 闭包。
    /// - Returns: `EventLoopRes<Void, S.Errcase>`
    func detach(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<S.QPrivilege, GResource>
        _ content: @Sendable @escaping () -> OrderedSet<MTMRelation<S.QPrivilege, GResource>>
    ) -> EventLoopRes<Void, S.Errcase>  {
        detach(relations: content(), on: transactor)
    }
}

public extension PrivilegeModule.PrivilegeController {
    // MARK: - 资源权限附加
    
    /// 将多对多关系批量写入底层 Pivot 中，建立权限与资源之间的映射（直接传参模式）。
    /// 附加权限动作要求资源与权限都必须已存在于数据库中，任一不存在都会导致失败。
    func attach(
        privilegeToResource relations: OrderedSet<MTMRelation<UUID, UUID>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, S.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 资源权限附加资源 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("资源权限附加资源关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            type: (S.QPrivilege.self, GResource.self),
            action: .attach,
            label: "资源权限与资源",
            errThrowing: .privilegeAttachResourceFailed,
            pivotType: PM.__DBM.PrivilegeAnyResource.self,
            checkList: .all
        )
        .map { _ in logger.info("资源权限附加资源 操作成功") }
    }
    
    /// 将多对多关系批量写入底层 Pivot 中，建立权限与资源之间的映射（直接传参模式）。
    /// 附加权限动作要求资源与权限都必须已存在于数据库中，任一不存在都会导致失败。
    func attach(
        relations: OrderedSet<MTMRelation<S.QPrivilege, GResource>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, S.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 资源权限附加资源 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("资源权限附加资源关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            action: .attach,
            label: "资源权限与资源",
            errThrowing: .privilegeAttachResourceFailed,
            pivotType: PM.__DBM.PrivilegeAnyResource.self
        )
        .map { _ in logger.info("资源权限附加资源 操作成功") }
    }
    
    // MARK: - 资源权限解除
    
    /// 从多对多 Pivot 中移除指定关系，切断权限与资源之间的关联（直接传参模式）。
    /// 解除权限动作的 Resource 无需从数据库中查得，可以实例化 AnyResource 类型的 Resource 并赋值 UUID。
    func detach(
        privilegeFromResource relations: OrderedSet<MTMRelation<UUID, UUID>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, S.Errcase>  {
        let logger = getActionLogger()
        logger.info("执行 资源权限解除资源 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("资源权限解除资源关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            type: (S.QPrivilege.self, GResource.self),
            action: .detach,
            label: "资源权限与资源",
            errThrowing: .privilegeDetachResourceFailed,
            pivotType: PM.__DBM.PrivilegeAnyResource.self,
            checkList: .all
        )
        .map { _ in logger.info("资源权限解除资源 操作成功") }
    }
    
    /// 从多对多 Pivot 中移除指定关系，切断权限与资源之间的关联（直接传参模式）。
    /// 解除权限动作的 Resource 无需从数据库中查得，可以实例化 AnyResource 类型的 Resource 并赋值 UUID。
    func detach(
        relations: OrderedSet<MTMRelation<S.QPrivilege, GResource>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, S.Errcase>  {
        let logger = getActionLogger()
        logger.info("执行 资源权限解除资源 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("资源权限解除资源关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            action: .detach,
            label: "资源权限与资源",
            errThrowing: .privilegeDetachResourceFailed,
            pivotType: PM.__DBM.PrivilegeAnyResource.self
        )
        .map { _ in logger.info("资源权限解除资源 操作成功") }
    }
}

// MARK: - 资源权限验证与查询

public extension PrivilegeModule.PrivilegeController {
    /// 取得附加到特定类型化资源的所有策略集。
    ///
    /// - Parameter resource: 需要探查的资源对象 `S.ResourceDTO<T, DTO.Queried>`。
    /// - Returns: 与该资源绑定的策略集合 `EventLoopRes<[S.QPrivilege], Errcase>`。
    func privilege<T: Resource>(
        attachedTo resource: S.QResource<T>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[S.QPrivilege], Errcase> {
        __privilege(on: transactor?.db ?? self.db, attachedTo: resource)
    }
    
    /// 取得附加到任意擦除类型资源上的所有策略集。
    ///
    /// - Parameter resource: 擦除了具体类型的资源包装体 `AnyResource`。
    /// - Returns: 与该资源绑定的策略集合 `EventLoopRes<[S.QPrivilege], Errcase>`。
    func privilege(
        attachedTo resource: GResource,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[S.QPrivilege], Errcase> {
        __privilege(on: transactor?.db ?? self.db, attachedTo: resource)
    }
}

public extension PrivilegeModule.PrivilegeController {
    /// 判定特定的策略对象是否正绑定于该具体类型资源之上。
    ///
    /// - Parameters:
    ///   - privilege: 需要检验是否存在的权限策略。
    ///   - resource: 目标探查对象资源。
    /// - Returns: 如果存在绑定关系则返回 `true`，否则 `false`。
    func `is`<T: Resource>(
        privilege: S.QPrivilege,
        attachedTo resource: S.QResource<T>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Bool, Errcase> {
        __is(on: transactor?.db ?? self.db, privilege: privilege, attachedTo: resource)
    }
    
    /// 判定特定的策略对象是否正绑定于该擦除类型资源之上。
    ///
    /// - Parameters:
    ///   - privilege: 需要检验是否存在的权限策略。
    ///   - resource: 目标探查对象资源 `AnyResource`。
    /// - Returns: 如果存在绑定关系则返回 `true`，否则 `false`。
    func `is`(
        privilege: S.QPrivilege,
        attachedTo resource: GResource,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Bool, Errcase> {
        __is(on: transactor?.db ?? self.db, privilege: privilege, attachedTo: resource)
    }
}

extension PrivilegeModule.PrivilegeController {
    // 取得 某资源 的所有资源权限
    func __privilege<T: Resource>(
        on db: PGDatabase,
        attachedTo resource: S.QResource<T>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[S.QPrivilege], Errcase> {
        let db = transactor?.db ?? self.db
        return resource.model(from: db)
            .errCast(Errcase.privilegeFetchFailed, "取得 Resource 主模型失败", category: .internal)
            .flatMap
        { resourceModel in
            resourceModel.$privileges.get(on: db)
                .withError(Errcase.privilegeFetchFailed, "从数据库查询失败", category: .internal)
        }.flatMapThrowing { privileges throws(Errcase.ErrType) in
            try required(throws: Errcase.privilegeFetchFailed, "转为 DTO 失败", category: .internal) {
                try privileges.map { try S.QPrivilege.make(from: $0).get() }
            }
        }
    }
    
    // 取得 某资源 的所有资源权限
    func __privilege(
        on db: PGDatabase,
        attachedTo resource: GResource,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[S.QPrivilege], Errcase> {
        let db = transactor?.db ?? self.db
        return S.__DBM.PrivilegeAnyResourcePivot.query(on: db)
            .filter(\.$secondaryModel.$id == resource.id)
            .with(\.$primaryModel)
            .all()
            .withError(Errcase.privilegeFetchFailed, "从数据库查询失败", category: .internal)
            .flatMapThrowing
        { maps throws(Errcase.ErrType) in
            try required(throws: Errcase.privilegeFetchFailed, "转为 DTO 失败", category: .internal) {
                try maps.map { try S.QPrivilege.make(from: $0.primaryModel).get() }
            }
        }
    }
}

extension PrivilegeModule.PrivilegeController {
    // 检查某权限是否被附加给某资源
    func __is<T: Resource>(
        on db: PGDatabase,
        privilege: S.QPrivilege,
        attachedTo resource: S.QResource<T>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Bool, Errcase> {
        let db = transactor?.db ?? self.db
        return resource.model(from: db)
            .errCast(Errcase.privilegeCheckFailed, "取得 Resource 主模型失败", category: .internal)
            .flatMap
        { resourceModel in
            resourceModel.$privileges.query(on: db)
                .filter(\.$id == privilege.id)
                .first()
                .withError(Errcase.privilegeCheckFailed, "从数据库查询失败", category: .internal)
                .map { $0 != nil }
        }
    }
    
    // 检查某权限是否被附加给某资源
    func __is(
        on db: PGDatabase,
        privilege: S.QPrivilege,
        attachedTo resource: GResource,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Bool, Errcase> {
        let db = transactor?.db ?? self.db
        return S.__DBM.PrivilegeAnyResourcePivot.query(on: db)
            .filter(\.$secondaryModel.$id == resource.id)
            .first()
            .withError(Errcase.privilegeFetchFailed, "从数据库查询失败", category: .internal)
            .map { $0 != nil }
    }
}
