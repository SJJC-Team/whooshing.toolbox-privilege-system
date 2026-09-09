import OPA

extension PrivilegeModule {
    func opaInitialize(logger: Logger) async throws(Errcase.ErrType) {
        let policies = try await logger.required(throws: Errcase.opaInitFailed, "从数据库查询资源权限数据失败", category: .internal) {
            try await __DBM.Privilege.query(on: pgDB).all().map {
                (
                    policyPath(moduleId: moduleId, modelId: nil, policyId: try $0.requireID(), type: __DBM.Privilege.self, format: .route),
                    $0.policy
                )
            }
        }
        
        for (path, policy) in policies {
            try await logger.required(throws: Errcase.opaInitFailed, "OPA 注入权限数据失败", category: .internal) {
                _ = try await opa.policy.save(by: path, content: assemblePolicy(path: path, policy: policy))
            }
        }
        
        logger.info("OPA 数据同步完成")
    }
}
