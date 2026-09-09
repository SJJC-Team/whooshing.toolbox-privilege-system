import OPA
import DTOBuilder

extension PrivilegeSystem {
    func opaInitialize(logger: Logger) async throws(Errcase.ErrType) {
        let rolePolicies = try await logger.required(throws: Errcase.opaInitFailed, "从数据库查询角色权限数据失败", category: .internal) {
            try await __SDBM.RolePolicy.query(on: pgDB).all().map {
                (
                    policyPath(moduleId: $0.moduleId, modelId: $0.$parent.id, policyId: try $0.requireID(), type: Role.self, format: .route),
                    $0.policy
                )
            }
        }
        
        let domainPolicies = try await logger.required(throws: Errcase.opaInitFailed, "从数据库查询域权限数据失败", category: .internal) {
            try await __SDBM.DomainPolicy.query(on: pgDB).all().map {
                (
                    policyPath(moduleId: $0.moduleId, modelId: $0.$parent.id, policyId: try $0.requireID(), type: Domain.self, format: .route),
                    $0.policy
                )
            }
        }
        
        for (path, policy) in rolePolicies + domainPolicies {
            try await logger.required(throws: Errcase.opaInitFailed, "OPA 同步注入权限数据失败", category: .internal) {
                _ = try await opa.policy.save(by: path, content: assemblePolicy(path: path, policy: policy))
            }
        }
        
        logger.info("OPA 数据同步完成")
    }
}
