import Testing
import Foundation
@testable import PrivilegeSystem

typealias RT = RoleTesting

@Suite("角色 测试集", .serialized, .enabled(if: TestingShared.dbListening && TestingShared.opaListening))
struct RoleTesting {
    
    @Test("开始测试")
    func start() async throws {
        while await TestingShared.testStage != .role {
            try await Task.sleep(nanoseconds: 250_000_000)
        }
    }
    
    nonisolated(unsafe) static var ids: OrderedSet<UUID> = []
    nonisolated(unsafe) static var policyIds: [[UUID]] = []
    
    static let roles: OrderedSet<PRole> = [
        .init(name: "SuperAdminRole", summary: "拥有全局控制面板访问权限"),
        .init(name: "EditorRole", summary: "可以编辑及发布内容"),
        .init(name: "ModeratorRole", summary: "可以审阅社区发言并封禁违规用户"),
        .init(name: "ObserverRole", summary: "只读权限角色"),
        .init(name: "SalesManager", summary: "销售部经理角色"),
        .init(name: "HRLead", summary: "人力资源总监角色"),
        .init(name: "QAAnalyst", summary: "测试分析师角色"),
        .init(name: "GuestRole", summary: "访客受限角色"),
        .init(name: "BillingAdmin", summary: "财务账单管理角色"),
        .init(name: "SecurityOfficer", summary: "安全合规管理角色"),
        .init(name: "DataScientist", summary: "数据科学家角色"),
        .init(name: "ProductManager", summary: "产品经理角色"),
        .init(name: "ContentReviewer", summary: "内容审核专员角色"),
        .init(name: "DevOpsEngineer", summary: "运维工程师角色")
    ]
    
    static let defaultPolicy: String = """
    allow if { true }
    """
    
    // 可以在这里为您定义的每一个角色自定义专属 Policy，如果为 nil 则会使用上面的 defaultPolicy
    // PolicyTests 关键内容：
    //   role0 (SuperAdminRole): input.operation == "manage_all"
    //   role1 (EditorRole)    : input.operation 为 "edit" 或 "publish"
    //   role2 (ModeratorRole) : input.operation == "moderate"
    //   role3 (ObserverRole)  : input.operation == "view"
    static let customPolicies: [String?] = [
        """
        allow if { input.operation == "manage_all" }
        """, // 0: SuperAdminRole
        """
        allow if { input.operation == "edit" }
        allow if { input.operation == "publish" }
        """, // 1: EditorRole
        """
        allow if { input.operation == "moderate" }
        """, // 2: ModeratorRole
        """
        allow if { input.operation == "view" }
        """, // 3: ObserverRole
        nil, // 4: SalesManager
        nil, // 5: HRLead
        nil, // 6: QAAnalyst
        nil, // 7: GuestRole
        nil, // 8: BillingAdmin
        nil, // 9: SecurityOfficer
        nil, // 10: DataScientist
        nil, // 11: ProductManager
        nil, // 12: ContentReviewer
        nil  // 13: DevOpsEngineer
    ]
    
    static var updates: [(PRole.Updater, String, @Sendable (QRole) -> Bool)] {[
        (
            .init(roleId: Self.ids[1]).update(name: "AdvancedEditorRole"),
            "将编辑角色更名",
            { $0.name == "AdvancedEditorRole" }
        ),
        (
            .init(roleId: Self.ids[3]).update(summary: "静默观察器"),
            "将观察角色描述更改",
            { $0.summary! == "静默观察器" }
        )
    ]}
    
    @Test("创建角色")
    func create() async throws {
        let (s, _) = try await TestingShared.getSystem()
        _ = try await s.role.create(roles: Self.roles)
    }
    
    @Test("查询并验证角色")
    func query() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        #expect(try await s.origin.query(QRole.self).filter(\.id != BasicRoleCreatesTesting.nobodyRoleId).count() == Self.roles.count)
        
        Self.ids = []
        Self.policyIds = []
        for roleParam in Self.roles {
            let u = try #require(
                try await s.origin.query(QRole.self)
                    .filter(\.name == roleParam.name)
                    .first()
                    
            )
            Self.ids.append(u.id)
        }
        #expect(Self.ids.count == Self.roles.count)
    }
    
    @Test("为每个角色创建默认策略")
    func createPolicies() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let allRoles = try await s.origin.query(QRole.self).all()
        let roles = Self.ids.compactMap { id in allRoles.first(where: { $0.id == id }) }
        
        for (i, role) in roles.enumerated() {
            let policyString = (i < Self.customPolicies.count ? Self.customPolicies[i] : nil) ?? Self.defaultPolicy
            
            let policy = PPolicy<Role>(
                moduleId: m.moduleId,
                policy: policyString
            )
            
            let policies = try await s.policy.createWithReturning(to: Role.self) {
                OrderedSet([policy]) => role.id
            }
            
            let ps = try #require(policies[role.id])
            
            Self.policyIds.append(ps.map { $0.id })
        }
        
        #expect(Self.policyIds.count == Self.ids.count)
    }
    
    @Test("验证角色策略是否成功添加")
    func verifyPolicies() async throws {
        let (s, _) = try await TestingShared.getSystem()
        let allRoles = try await s.origin.query(QRole.self).all()
        let roles = Self.ids.compactMap { id in allRoles.first(where: { $0.id == id }) }
        for role in roles {
            let policies = try await __SDBM.PolicyExp<Role>.query(on: s.pgDB)
                .filter(\.$parent.$id == role.id)
                .all()
            
            #expect(!policies.isEmpty, "角色 \(role.name) 应当至少包含一条关联策略")
        }
    }

    @Test("createWithReturning 返回正确的 QPolicy 字典（Role 类型）")
    func createWithReturning_RolePolicy() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let targetId = Self.ids[13] // DevOpsEngineer

        let existing = try await __SDBM.PolicyExp<Role>.query(on: s.pgDB)
            .filter(\.$parent.$id == targetId).all()
        for p in existing {
            let qp = try QPolicy<Role>.make(from: p).get()
            try await s.policy.delete(from: Role.self, policy: qp => targetId)
        }

        let newPolicy = PPolicy<Role>(
            moduleId: m.moduleId,
            policy: "allow if { input.operation == \"devops\" }"
        )
        let returned = try await s.policy.createWithReturning(to: Role.self) {
            OrderedSet([newPolicy]) => targetId
        }

        let policies = try #require(returned[targetId], "返回字典中应有 targetId 对应的条目")
        #expect(policies.count == 1)
        #expect(policies[0].moduleId == m.moduleId)
        #expect(policies[0].policy.contains("devops"))

        for qp in policies {
            try await s.policy.delete(from: Role.self, policy: qp => targetId)
        }
        let def = PPolicy<Role>(moduleId: m.moduleId, policy: "allow if { true }")
        try await s.policy.create(to: Role.self) { OrderedSet([def]) => targetId }
    }

    @Test("Role 策略删除：从 DB 移除，计数减少 1，并可恢复")
    func rolePolicy_DeleteAndRestore() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let targetId = Self.ids[12] // ContentReviewer

        let before = try await __SDBM.PolicyExp<Role>.query(on: s.pgDB)
            .filter(\.$parent.$id == targetId).all()
        guard let first = before.first else {
            Issue.record("RT.ids[12](ContentReviewer) 应有策略")
            return
        }

        let qp = try QPolicy<Role>.make(from: first).get()
        try await s.policy.delete(from: Role.self, policy: qp => targetId)

        let after = try await __SDBM.PolicyExp<Role>.query(on: s.pgDB)
            .filter(\.$parent.$id == targetId).count()
        #expect(after == before.count - 1, "删除后应少 1 条")

        let def = PPolicy<Role>(moduleId: m.moduleId, policy: "allow if { true }")
        try await s.policy.create(to: Role.self) { OrderedSet([def]) => targetId }
        let restored = try await __SDBM.PolicyExp<Role>.query(on: s.pgDB)
            .filter(\.$parent.$id == targetId).count()
        #expect(restored == before.count, "恢复后数量应与原来一致")
    }
    
    @Test("角色更新测试")
    func update() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        for (updater, msg, verifier) in Self.updates {
            let res = try await s.role.update(with: updater)
            #expect(verifier(res), "验证失败: \(msg)")
        }
    }
    
    @Test("角色多重关联与撤除测试")
    func appointAndDismissAll() async throws {
        let (s, _) = try await TestingShared.getSystem()
        let users = try await s.origin.query(QUser.self).all()
        let groups = try await s.origin.query(QGroup.self).all()
        let roles = try await s.origin.query(QRole.self).all().filter { role in
            role.name != "nobody"
        }
        
        let user = users[1]
        let group = groups[1]
        let role = roles[1]
        
        // 1. Role <-> User
        try await s.role.appoint { OrderedSet([role]) => OrderedSet([user]) }
        let c1 = try await __SDBM.UserRolePivot.query(on: s.pgDB)
            .filter(\.$secondaryModel.$id != BasicRoleCreatesTesting.nobodyRoleId)
            .count()
        #expect(c1 == 1)
        try await s.role.dismiss { OrderedSet([role]) => OrderedSet([user]) }
        let c2 = try await __SDBM.UserRolePivot.query(on: s.pgDB)
            .filter(\.$secondaryModel.$id != BasicRoleCreatesTesting.nobodyRoleId)
            .count()
        #expect(c2 == 0)

        // 2. Role <-> Group
        try await s.role.appoint { OrderedSet([role]) => OrderedSet([group]) }
        let c3 = try await __SDBM.RoleGroupPivot.query(on: s.pgDB)
            .filter(\.$primaryModel.$id != BasicRoleCreatesTesting.nobodyRoleId)
            .count()
        #expect(c3 == 1)
        try await s.role.dismiss { OrderedSet([role]) => OrderedSet([group]) }
        let c4 = try await __SDBM.RoleGroupPivot.query(on: s.pgDB)
            .filter(\.$primaryModel.$id != BasicRoleCreatesTesting.nobodyRoleId)
            .count()
        #expect(c4 == 0)

        // 3. Role <-> UserInGroup
        // 先建立 User <-> Group 关系才能指派组内用户的角色
        try await s.group.join { OrderedSet([user]) => OrderedSet([group]) }
        let uig = try await s.group.query(relations: [.init(userId: user.id, groupId: group.id)])
        try await s.role.appoint { OrderedSet([role]) => OrderedSet(uig) }
        let c5 = try await __SDBM.RoleUserInGroupPivot.query(on: s.pgDB)
            .filter(\.$primaryModel.$id != BasicRoleCreatesTesting.nobodyRoleId)
            .count()
        #expect(c5 == 1)
        try await s.role.dismiss { OrderedSet([role]) => OrderedSet(uig) }
        let c6 = try await __SDBM.RoleUserInGroupPivot.query(on: s.pgDB)
            .filter(\.$primaryModel.$id != BasicRoleCreatesTesting.nobodyRoleId)
            .count()
        #expect(c6 == 0)
        
        // 扫尾清理 User <-> Group
        try await s.group.kick { OrderedSet([user]) => OrderedSet([group]) }
    }
    
    @Test("角色删除测试")
    func delete() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        // 临时创建一个角色用于删除测试
        let tempRole = try await s.role.create(roles: [
            .init(name: "TempDeleteRole", summary: "临时删除测试角色")
        ])
        
        let countBefore = try await s.origin.query(QRole.self)
            .filter(\.id != BasicRoleCreatesTesting.nobodyRoleId)
            .count()
        #expect(countBefore == Self.roles.count + 1)
        
        let tempId = try #require(tempRole.first?.id)
        try await s.role.delete(roleIds: [tempId])
        
        let countAfter = try await s.origin.query(QRole.self)
            .filter(\.id != BasicRoleCreatesTesting.nobodyRoleId)
            .count()
        #expect(countAfter == Self.roles.count, "删除后角色数量应恢复")
        
        let found = try await s.origin.query(QRole.self)
            .filter(\.name == "TempDeleteRole")
            .first()
        #expect(found == nil, "被删除的角色不应被查询到")
        
        // 删除不存在的关系，应当报错
        let nonExistentId = UUID()
        await #expect(throws: PrivilegeSystem.Errcase.ErrType.self) {
            try await s.role.delete(roleIds: [nonExistentId])
        }
    }

    @Test("清理验证：所有角色均至少有 1 条策略")
    func cleanup_AllRolesHavePolicies() async throws {
        let (s, _) = try await TestingShared.getSystem()
        for (i, roleId) in Self.ids.enumerated() {
            let count = try await __SDBM.PolicyExp<Role>.query(on: s.pgDB)
                .filter(\.$parent.$id == roleId).count()
            if count < 1 {
                Issue.record("RT.ids[\(i)] 角色应至少有 1 条策略，当前 \(count) 条")
            }
        }
    }
    
    @MainActor
    @Test("测试结束")
    func end() async throws {
        TestingShared.testStage = .init(rawValue: TestingShared.testStage.rawValue + 1)!
    }
}
