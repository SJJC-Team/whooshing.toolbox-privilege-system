import PrivilegeModule

extension PrivilegeSystem {
    public final class PolicyController: SystemOPAController {
        package let db: PGDatabase
        package let eventLoop: EventLoop
        package let opa: OPA
        
        /// 操作记录日志器。
        public let logger: Logger
        
        init(
            db: PGDatabase,
            eventLoop: EventLoop,
            opa: OPA,
            logger: Logger
        ) {
            self.db = db
            self.eventLoop = eventLoop
            self.opa = opa
            self.logger = logger
        }
        
        /// 批量创建并绑定系统级策略（使用链式构造器模式）。
        ///
        /// 系统级策略（如角色策略、域策略）被直接指派到对应的实体模型上。
        /// 创建成功后，OPA 将自动载入新分配的策略。
        ///
        /// - Parameters:
        ///   - model: 目标策略类型（如 `Role.self` 或 `Domain.self`）。
        ///   - content: `@MTORelationBuilder` 闭包，用于声明策略对象与实体 UUID 的关系。
        /// - Returns: `EventLoopRes<Void, PrivilegeSystem.Errcase>`
        public func create<T: PolicyType>(
            on transactor: Transactor? = nil,
            to model: T.Type,
            @MTORelationBuilder<PPolicy<T>, T.Model.IDValue>
            _ content: @Sendable @escaping () -> OrderedSet<MTORelation<PPolicy<T>, T.Model.IDValue>>
        ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
            let logger = getActionLogger()
            logger.info("执行 创建策略 操作", metadata: ["type": .string(String(describing: model))])
            return create(to: model, relations: content(), on: transactor)
                .map { logger.info("创建策略 操作成功") }
                .logIfFail(logger: logger)
        }
        
        /// 批量创建、绑定系统级策略，并在成功后返回完整的查询状态策略 DTO。
        ///
        /// 与 `create` 类似，但在写入数据库和同步 OPA 成功后，会提取出包含已分配 UUID 和正确元数据的 `DTO.Queried` 状态对象。
        /// 这对于后续修改或删除策略操作至关重要。
        ///
        /// - Parameters:
        ///   - model: 目标策略类型（如 `Role.self` 或 `Domain.self`）。
        ///   - content: `@MTORelationBuilder` 闭包。
        /// - Returns: 按绑定的目标模型 ID 分组的策略列表 `EventLoopRes<[T.Model.IDValue: [QPolicy<T>]], PrivilegeSystem.Errcase>`。
        public func createWithReturning<T: PolicyType>(
            on transactor: Transactor? = nil,
            to model: T.Type,
            @MTORelationBuilder<PPolicy<T>, T.Model.IDValue>
            _ content: @Sendable @escaping () -> OrderedSet<MTORelation<PPolicy<T>, T.Model.IDValue>>
        ) -> EventLoopRes<[T.Model.IDValue: [QPolicy<T>]], PrivilegeSystem.Errcase> {
            let logger = getActionLogger()
            logger.info("执行 创建策略（返回） 操作", metadata: ["type": .string(String(describing: model))])
            return createWithReturning(to: model, relations: content(), on: transactor)
                .map { logger.info("创建策略（返回） 操作成功"); return $0 }
                .logIfFail(logger: logger)
        }
        
        /// 删除指定的系统级策略。
        ///
        /// 策略一旦删除，会立刻同步移除 OPA 中的相关判定规则。这可能改变现存成员的访问权限。
        ///
        /// - Parameters:
        ///   - model: 目标策略类型（如 `Role.self` 或 `Domain.self`）。默认为自身。
        ///   - policy: 一个 1:1 关系描述体，指明要删除的具体策略对象及其从属的实体 UUID。
        /// - Returns: `EventLoopRes<Void, PrivilegeSystem.Errcase>`
        public func delete<T: PolicyType>(
            from model: T.Type = T.self,
            policy: OTORelation<QPolicy<T>, T.Model.IDValue>,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
            let logger = getActionLogger()
            logger.info("执行 删除策略 操作", metadata: ["type": .string(String(describing: model)), "policyId": .stringConvertible(policy.left.id)])
            let db = transactor?.db ?? self.db
            return __deletePolicy(
                on: db,
                policy: policy,
                policyType: T.self,
                label: "权限策略",
                errThrowing: .policyDeleteFailed,
                filterBuilder: {
                    __SDBM.PolicyExp<T>
                        .query(on: $0)
                        .filter(\.$id == policy.left.id)
                },
                moduleId: { $0.left.moduleId },
                policyId: { $0.left.id },
                modelIdKey: \.right,
                opaPathHaveModelId: true
            )
            .map { logger.info("删除策略 操作成功") }
            .logIfFail(logger: logger)
        }
    }
}

public extension PrivilegeSystem.PolicyController {
    /// 批量创建并绑定系统级策略（直接传参模式）。
    ///
    /// - Parameters:
    ///   - model: 目标策略类型（如 `Role.self` 或 `Domain.self`）。
    ///   - relations: 策略与实体对应关系的数组。
    /// - Returns: `EventLoopRes<Void, PrivilegeSystem.Errcase>`
    func create<T: PolicyType>(
        to model: T.Type,
        relations: OrderedSet<MTORelation<PPolicy<T>, T.Model.IDValue>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 创建策略（数组） 操作", metadata: ["type": .string(String(describing: model)), "relations": .summaryData(relations)])
        logger.debug("操作参数", metadata: ["relations": .data(relations)])
        let db = transactor?.db ?? self.db
        return __create(on: db, to: model, relations: relations)
            .map { _ in logger.info("创建策略（数组） 操作成功") }
            .logIfFail(logger: logger)
    }
    
    /// 批量创建并绑定系统级策略，同时返回插入后的结果（直接传参模式）。
    ///
    /// - Parameters:
    ///   - model: 目标策略类型（如 `Role.self` 或 `Domain.self`）。
    ///   - relations: 策略与实体对应关系的数组。
    /// - Returns: 按实体 ID 分组返回所有被分配的查询状态策略。
    func createWithReturning<T: PolicyType>(
        to model: T.Type,
        relations: OrderedSet<MTORelation<PPolicy<T>, T.Model.IDValue>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[T.Model.IDValue: [QPolicy<T>]], PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 创建策略（数组返回） 操作", metadata: ["type": .string(String(describing: model)), "relations": .summaryData(relations)])
        logger.debug("操作参数", metadata: ["relations": .data(relations)])
        let db = transactor?.db ?? self.db
        return __createWithReturning(on: db, to: model, relations: relations)
            .map { logger.info("创建策略（数组返回） 操作成功"); return $0 }
            .logIfFail(logger: logger)
    }
}

extension PrivilegeSystem.PolicyController {
    func __create<T: PolicyType>(
        on db: PGDatabase,
        to model: T.Type,
        relations: OrderedSet<MTORelation<PPolicy<T>, T.Model.IDValue>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        __createPolicy(
            on: db,
            relations: relations,
            policyType: T.self,
            label: "权限策略",
            errThrowing: .policyCreateFailed,
            policies: \.left,
            moduleId: \.moduleId,
            policyKey: \.policy,
            modelId: { pr, _ in pr.right },
            policyIdSetter: { $0.set(id: $1) },
            modelBuilder: { $0.raw(parentId: $1) },
            opaPathHaveModelId: true
        ).map { _ in }
    }
    
    func __createWithReturning<T: PolicyType>(
        on db: PGDatabase,
        to model: T.Type,
        relations: OrderedSet<MTORelation<PPolicy<T>, T.Model.IDValue>>
    ) -> EventLoopRes<[T.Model.IDValue: [QPolicy<T>]], PrivilegeSystem.Errcase> {
        __createPolicy(
            on: db,
            relations: relations,
            policyType: T.self,
            label: "权限策略",
            errThrowing: .policyCreateFailed,
            policies: \.left,
            moduleId: \.moduleId,
            policyKey: \.policy,
            modelId: { pr, _ in pr.right },
            policyIdSetter: { $0.set(id: $1) },
            modelBuilder: { $0.raw(parentId: $1) },
            opaPathHaveModelId: true
        ).flatMapThrowing { ps throws(PrivilegeSystem.Errcase.ErrType) in
            try required(throws: PrivilegeSystem.Errcase.policyCreateFailed, "Returning 解包失败", category: .internal) {
                try ps.grouped {
                    $0.$parent.id
                }.mapValues { v in
                    try v.map {
                        try QPolicy<T>.make(from: $0).get()
                    }
                }
            }
        }
    }
}
