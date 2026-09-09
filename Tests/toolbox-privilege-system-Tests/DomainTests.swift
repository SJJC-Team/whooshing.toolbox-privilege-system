import Testing
import Foundation
@testable import PrivilegeSystem

typealias DT = DomainTesting

@Suite("域权限 测试集", .serialized, .enabled(if: TestingShared.dbListening && TestingShared.opaListening))
struct DomainTesting {
    
    @Test("开始测试")
    func start() async throws {
        while await TestingShared.testStage != .domain {
            try await Task.sleep(nanoseconds: 250_000_000)
        }
    }
    
    nonisolated(unsafe) static var ids: OrderedSet<UUID> = []
    nonisolated(unsafe) static var policyIds: [[UUID]] = []
    
    static let domains: OrderedSet<PDomain> = [
        .init(name: "GlobalScope", summary: "全系统顶级域，可以影响所有资源"),
        .init(name: "AsiaPacific", summary: "亚太地区业务域"),
        .init(name: "NorthAmerica", summary: "北美地区业务域"),
        .init(name: "SandboxEnvironment", summary: "仅限内部访问的隔离沙盒域"),
        .init(name: "Europe", summary: "欧洲业务域"),
        .init(name: "SouthAmerica", summary: "南美洲业务域"),
        .init(name: "Africa", summary: "非洲业务域"),
        .init(name: "InternalOnly", summary: "仅限内网访问"),
        .init(name: "PublicFacing", summary: "面向公众的服务域"),
        .init(name: "Development", summary: "开发环境域"),
        .init(name: "Staging", summary: "预发布环境域"),
        .init(name: "Production", summary: "生产环境域"),
        .init(name: "LegacySystem", summary: "遗留老系统域"),
        .init(name: "PartnerNetwork", summary: "合作伙伴网络域")
    ]
    
    static let defaultPolicy: String = """
    allow if { true }
    """
    
    // 可以在这里为您定义的每一个域自定义专属 Policy，如果为 nil 则会使用上面的 defaultPolicy
    // PolicyTests 关键内容：
    //   domain0 (GlobalScope)       : input.resource.global == true
    //   domain1 (AsiaPacific)       : input.resource.region == "asia"
    //   domain2 (NorthAmerica)      : input.resource.region == "na"
    //   domain3 (SandboxEnvironment): input.resource.env == "sandbox"
    static let customPolicies: [String?] = [
        """
        allow if { input.resource.global == true }
        """, // 0: GlobalScope
        """
        allow if { input.resource.region == "asia" }
        """, // 1: AsiaPacific
        """
        allow if { input.resource.region == "na" }
        """, // 2: NorthAmerica
        """
        allow if { input.resource.env == "sandbox" }
        """, // 3: SandboxEnvironment
        nil, // 4: Europe
        nil, // 5: SouthAmerica
        nil, // 6: Africa
        nil, // 7: InternalOnly
        nil, // 8: PublicFacing
        nil, // 9: Development
        nil, // 10: Staging
        nil, // 11: Production
        nil, // 12: LegacySystem
        nil  // 13: PartnerNetwork
    ]
    
    static var updates: [(PDomain.Updater, String, @Sendable (QDomain) -> Bool)] {[
        (
            .init(domainId: Self.ids[2]).update(name: "NAMERegion"),
            "尝试更新第三个域的名称标识",
            { $0.name == "NAMERegion" }
        )
    ]}
    
    @Test("创建域")
    func create() async throws {
        let (s, _) = try await TestingShared.getSystem()
        _ = try await s.domain.create(domains: Self.domains)
    }
    
    @Test("查询域信息和组装")
    func query() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        #expect(try await s.origin.query(QDomain.self).count() == Self.domains.count)
        
        Self.ids = []
        Self.policyIds = []
        for domainParam in Self.domains {
            let u = try #require(
                try await s.origin.query(QDomain.self)
                    .filter(\.name == domainParam.name)
                    .first()
                    
            )
            Self.ids.append(u.id)
        }
        #expect(Self.ids.count == Self.domains.count)
    }
    
    @Test("为每个域创建默认策略")
    func createPolicies() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let allDomains = try await s.origin.query(QDomain.self).all()
        let domains = Self.ids.compactMap { id in allDomains.first(where: { $0.id == id }) }
        
        for (i, domain) in domains.enumerated() {
            let policyString = (i < Self.customPolicies.count ? Self.customPolicies[i] : nil) ?? Self.defaultPolicy
            
            let policy = PPolicy<Domain>(
                moduleId: m.moduleId,
                policy: policyString
            )
            let policies = try await s.policy.createWithReturning(to: Domain.self) {
                OrderedSet([policy]) => domain.id
            }
            
            let ps = try #require(policies[domain.id])
            
            Self.policyIds.append(ps.map { $0.id })
        }
        
        #expect(Self.policyIds.count == Self.ids.count)
    }
    
    @Test("验证域策略是否成功添加")
    func verifyPolicies() async throws {
        let (s, _) = try await TestingShared.getSystem()
        let allDomains = try await s.origin.query(QDomain.self).all()
        let domains = Self.ids.compactMap { id in allDomains.first(where: { $0.id == id }) }
        
        for domain in domains {
            let policies = try await __SDBM.PolicyExp<Domain>.query(on: s.pgDB)
                .filter(\.$parent.$id == domain.id)
                .all()
            
            #expect(!policies.isEmpty, "域 \(domain.name) 应当至少包含一条关联策略")
        }
    }

    @Test("createWithReturning 返回正确的 QPolicy 字典（Domain 类型）")
    func createWithReturning_DomainPolicy() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let targetId = Self.ids[13] // PartnerNetwork

        let existing = try await __SDBM.PolicyExp<Domain>.query(on: s.pgDB)
            .filter(\.$parent.$id == targetId).all()
        for p in existing {
            let qp = try QPolicy<Domain>.make(from: p).get()
            try await s.policy.delete(from: Domain.self, policy: qp => targetId)
        }

        let newPolicy = PPolicy<Domain>(
            moduleId: m.moduleId,
            policy: "allow if { input.resource.partner == true }"
        )
        let returned = try await s.policy.createWithReturning(to: Domain.self) {
            OrderedSet([newPolicy]) => targetId
        }

        let policies = try #require(returned[targetId])
        #expect(policies.count == 1)
        #expect(policies[0].policy.contains("partner"))

        for qp in policies {
            try await s.policy.delete(from: Domain.self, policy: qp => targetId)
        }
        let def = PPolicy<Domain>(moduleId: m.moduleId, policy: "allow if { true }")
        try await s.policy.create(to: Domain.self) { OrderedSet([def]) => targetId }
    }

    @Test("Domain 策略删除：从 DB 移除，计数减少 1，并可恢复")
    func domainPolicy_DeleteAndRestore() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let targetId = Self.ids[12] // LegacySystem

        let before = try await __SDBM.PolicyExp<Domain>.query(on: s.pgDB)
            .filter(\.$parent.$id == targetId).all()
        guard let first = before.first else {
            Issue.record("DT.ids[12](LegacySystem) 应有策略")
            return
        }

        let qp = try QPolicy<Domain>.make(from: first).get()
        try await s.policy.delete(from: Domain.self, policy: qp => targetId)

        let after = try await __SDBM.PolicyExp<Domain>.query(on: s.pgDB)
            .filter(\.$parent.$id == targetId).count()
        #expect(after == before.count - 1, "删除后应少 1 条")

        let def = PPolicy<Domain>(moduleId: m.moduleId, policy: "allow if { true }")
        try await s.policy.create(to: Domain.self) { OrderedSet([def]) => targetId }
        let restored = try await __SDBM.PolicyExp<Domain>.query(on: s.pgDB)
            .filter(\.$parent.$id == targetId).count()
        #expect(restored == before.count, "恢复后数量应与原来一致")
    }
    
    @Test("域信息状态更新")
    func update() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        for (updater, msg, verifier) in Self.updates {
            let res = try await s.domain.update(with: updater)
            #expect(verifier(res), "验证失败: \(msg)")
        }
    }
    
    @Test("域多重关联与撤除测试")
    func assignAndUnassignAll() async throws {
        let (s, _) = try await TestingShared.getSystem()
        let users = try await s.origin.query(QUser.self).all()
        let groups = try await s.origin.query(QGroup.self).all()
        let domains = try await s.origin.query(QDomain.self).all()
        
        let user = users[2]
        let group = groups[2]
        let domain = domains[2]
        
        // 1. Domain <-> User
        try await s.domain.assign { OrderedSet([domain]) => OrderedSet([user]) }
        let count1 = try await __SDBM.UserDomainPivot.query(on: s.pgDB)
            .count()
        #expect(count1 == 1)
        try await s.domain.unassign { OrderedSet([domain]) => OrderedSet([user]) }
        let count2 = try await __SDBM.UserDomainPivot.query(on: s.pgDB)
            .count()
        #expect(count2 == 0)

        // 2. Domain <-> Group
        try await s.domain.assign { OrderedSet([domain]) => OrderedSet([group]) }
        let count3 = try await __SDBM.DomainGroupPivot.query(on: s.pgDB)
            .count()
        #expect(count3 == 1)
        try await s.domain.unassign { OrderedSet([domain]) => OrderedSet([group]) }
        let count4 = try await __SDBM.DomainGroupPivot.query(on: s.pgDB)
            .count()
        #expect(count4 == 0)
    }
    
    @Test("域删除测试")
    func delete() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        let tempDomain = try await s.domain.create(domains: [
            .init(name: "TempDeleteDomain", summary: "临时删除测试域")
        ])
        
        let countBefore = try await s.origin.query(QDomain.self).count()
        #expect(countBefore == Self.domains.count + 1)
        
        let tempId = try #require(tempDomain.first?.id)
        try await s.domain.delete(domainIds: [tempId])
        
        let countAfter = try await s.origin.query(QDomain.self).count()
        #expect(countAfter == Self.domains.count, "删除后域数量应恢复")
        
        let found = try await s.origin.query(QDomain.self)
            .filter(\.name == "TempDeleteDomain")
            .first()
        #expect(found == nil, "被删除的域不应被查询到")
        
        // 删除不存在内容，应当报错
        let nonExistentId = UUID()
        await #expect(throws: PrivilegeSystem.Errcase.ErrType.self) {
            try await s.domain.delete(domainIds: [nonExistentId])
        }
    }

    @Test("清理验证：所有域均至少有 1 条策略")
    func cleanup_AllDomainsHavePolicies() async throws {
        let (s, _) = try await TestingShared.getSystem()
        for (i, domainId) in Self.ids.enumerated() {
            let count = try await __SDBM.PolicyExp<Domain>.query(on: s.pgDB)
                .filter(\.$parent.$id == domainId).count()
            if count < 1 {
                Issue.record("DT.ids[\(i)] 域应至少有 1 条策略，当前 \(count) 条")
            }
        }
    }
    
    @MainActor
    @Test("测试结束")
    func end() async throws {
        TestingShared.testStage = .init(rawValue: TestingShared.testStage.rawValue + 1)!
    }
}
