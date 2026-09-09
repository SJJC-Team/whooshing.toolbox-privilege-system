import OPA
import Foundation
import NIOHTTP1

package protocol OPAController: Controller {
    var opa: OPA { get }
}

package extension OPAController {
    // 创建 OPA 策略并记录在数据库中
    // Pr: 策略与其所属模型的关系 Policy Relation
    // P: 策略 Policy
    // M: Fluent 模型，可直接存取数据库
    // PT: 策略类型，包括 Domain, Role, Privilege
    func __createPolicy<Relation: Sendable, Policy: Sendable, M: PGModel, PT: PolicyType>(
        on db: PGDatabase,
        relations: OrderedSet<Relation>,                // 待创建策略，同时每个策略绑定一个所属模型
        policyType: PT.Type,                            // 策略的类型，包括 Domain, Role, Privilege
        label: String,
        errThrowing: E,
        policies: (Relation) ->OrderedSet<Policy>,      // 从一条关系中列出所有相关的 Policies
        moduleId: @Sendable (Policy) -> UUID,           // 给出一个 Policy，返回其服务模块的 ID 号
        policyKey: KeyPath<Policy, String>,             // 指出 Policy 的 OPA 代码属性
        modelId: (Relation, Policy) -> UUID,            // 要求返回策略所绑定的所属模型的 ID 号
        policyIdSetter: (Policy, UUID) -> Policy,       // 要求 Policy 设置 ID 号
        modelBuilder: (Policy, UUID) -> M,              // 根据提供的 Policy 和 [所属模型的 ID 号] 创建具体的 Policy Fluent 模型
        opaPathHaveModelId: Bool
    ) -> EventLoopRes<[M], E> {
        // 准备 policy 容器，存储每个对应 policy 的对应路径及其 策略内容
        // 用于后续存取 OPA
        var psData: [(id: String, content: String)] = []
        
        // 准备要创建到 数据库中 的数据
        // 内容均为 Policy Fluent 模型
        let ps: [M] = relations.flatMap { relation in
            policies(relation).map { (policyWithoutId: Policy) in
                let pId = UUID()
                let policy = policyIdSetter(policyWithoutId, pId)
                
                // 准备路径，要放在 opa 中的位置
                let path = policyPath(
                    moduleId: moduleId(policy),
                    modelId: opaPathHaveModelId ? modelId(relation, policy): nil,
                    policyId: pId,
                    type: PT.self,
                    format: .route
                )
                
                // 准备 policy 的具体内容
                let policyStr = assemblePolicy(
                    path: path,
                    policy: policy[keyPath: policyKey]
                )
                
                // 收集 路径 和 策略内容
                psData.append((path, policyStr))
                
                // 创建 Fluent 模型
                return modelBuilder(policy, modelId(relation, policy))
            }
        }
        
        let progress = ProgressBox()
        let opaPolicyData = psData
        
        // 在 SQL 事务中，先执行 SQL 插入，保持该事务会话
        // 只有当 OPA 也插入成功后才提交事务
        // 否则，无论 SQL 或 OPA 插入失败，数据库与 OPA 都会进行回滚
        // 其中 OPA 回滚是通过删除已增加的策略实现的
        return db.trans(throws: errThrowing, "数据库事务执行失败", category: .internal) { db in
            // 先在数据库中创建所有 policy 数据
            ps
                .create(on: db)
                .withError(errThrowing, "\(policyType) 数据库插入 \(label) 策略失败", category: .internal)
                .flatMap
            {
                let target = db.eventLoop.makeTarget(of: Void.self, throws: E.ErrType.self)
                
                // 并行执行批量创建任务
                Task {
                    do {
                        try await withThrowingTaskGroup { group in
                            // id 为 opa 路径，content 为 策略规则内容
                            for (i, (id, content)) in opaPolicyData.enumerated() {
                                group.addTask {
                                    _ = try await required(throws: errThrowing, "\(policyType) 类型 OPA \(label)策略插入失败", category: .internal) {
                                        try await self.opa.policy.save(by: id, content: content)
                                    }
                                    
                                    // 记录创建进程
                                    progress.append(index: i)
                                }
                            }
                            try await group.waitForAll()
                        }
                        
                        target.succeed()
                    } catch let err {
                        let error = errThrowing.d("\(policyType) 类型 OPA \(label)策略并行任务时插入失败", category: .internal).subErr(err)
                        target.fail(error)
                    }
                }
                
                return target.futureResult.map { ps }
            }.flatMapError { error in
                // 任何一条失败将停止任务，且进行回滚
                undo(policies: opaPolicyData, progress: progress).flatMap {
                    self.eventLoop.makeFailedResult(error)
                }
            }
        }
        
        // 回滚操作，并行删除先前所创建的，并且忽略错误
        // 但若回滚失败，会 log critical 错误到日志系统
        @Sendable func undo(
            policies: [(id: String, content: String)],
            progress: ProgressBox
        ) -> EventLoopRes<Void, E> {
            .whenAllComplete(
                progress.indexes.reversed().map {
                    let (id, _) = policies[$0]
                    return self.opa.policy.delete(of: id)
                        .errCast(errThrowing, "\(policyType) 类型 OPA 回退失败，产生\(label)策略残留", category: .internal)
                        .map { _ in }
                },
                on: eventLoop
            )
            .map { _ in }
            .flatMapError { _ in
                self.eventLoop.makeSucceededVoidResult()
            }
        }
    }
    
    func __deletePolicy<Policy: Sendable, M: PGModel, PT: PolicyType>(
        on db: PGDatabase,
        policy: Policy,
        policyType: PT.Type,
        label: String,
        errThrowing: E,
        filterBuilder: @escaping @Sendable (PGDatabase) -> QueryBuilder<M>,
        moduleId: @Sendable (Policy) -> UUID,
        policyId: @Sendable (Policy) -> UUID,
        modelIdKey: KeyPath<Policy, UUID>,
        opaPathHaveModelId: Bool
    ) -> EventLoopRes<Void, E> {
        let path = policyPath(
            moduleId: moduleId(policy),
            modelId: opaPathHaveModelId ? policy[keyPath: modelIdKey] : nil,
            policyId: policyId(policy),
            type: PT.self,
            format: .route
        )
        
        // 在 SQL 事务中，先执行 SQL 删除，保持该事务会话
        // 只有当 OPA 也删除成功后才提交事务
        // 否则，无论 SQL 或 OPA 删除失败，数据库会进行回滚
        // 而 OPA 无需进行回滚，因为仅处理一条策略数据，
        // 删除失败意味着其仍在 OPA 中
        return db.trans(throws: errThrowing, "数据库事务执行失败", category: .internal) { db in
            filterBuilder(db)
                .count()
                .withError(errThrowing, "从 \(policyType) 数据库中查询要删除的数据 \(label) 失败", category: .internal)
                .flatMap
            { count in
                guard count > 0 else {
                    return db.eventLoop.makeFailedResult(errThrowing, "\(policyType) 数据库中不存在要删除的数据", category: .external(userdata: .init(HTTPResponseStatus.unprocessableEntity)))
                }
                
                return db.eventLoop.makeSucceededVoidResult()
            }.flatMap {
                filterBuilder(db)
                    .delete()
                    .withError(errThrowing, "从 \(policyType) 数据库中删除 \(label) 失败", category: .internal)
            }.flatMap {
                self.opa.policy.delete(of: path)
                    .errCast(errThrowing, "从 OPA 删除 \(policyType) 类型的 \(label) 失败", category: .internal)
                    .map { _ in }
            }
        }
    }
}

package final class ProgressBox: @unchecked Sendable {
    private let lock = NIOLock()
    private var _value: [Int] = []
    
    package var indexes: [Int] {
        lock.withLock { _value }
    }
    
    package func append(index: Int) {
        lock.withLock {
            _value.append(index)
        }
    }
}
