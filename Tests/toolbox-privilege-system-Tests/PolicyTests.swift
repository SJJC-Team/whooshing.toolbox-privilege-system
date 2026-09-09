import Testing
import Foundation
import Query
@testable import PrivilegeSystem

typealias PT = PolicyTesting

// =============================================================================
// PolicyTests.swift
// =============================================================================
// 本测试套件覆盖 PrivilegeSystem 中所有与策略鉴权相关的核心场景。
//
// 【关键设计】: 所有模型均通过前置测试套件保存的静态 ID 数组查询，
//              不使用名称查询（避免 DB 排序不确定性导致 OPA path 不匹配）。
//   AT.ids[i] → users 数组中第 i 个用户的 UUID
//   GT.ids[i] → groups 数组中第 i 个群组的 UUID
//   RT.ids[i] → roles 数组中第 i 个角色的 UUID
//   DT.ids[i] → domains 数组中第 i 个域的 UUID
//
// 【测试环境布局】（来自 Shared.swift 映射表）
//
//   角色策略（RoleTests 中创建，按 RT.ids 顺序）:
//     RT.ids[0] = SuperAdminRole  : allow if { input.operation == "manage_all" }
//     RT.ids[1] = EditorRole      : allow if { input.operation == "edit" OR "publish" }
//     RT.ids[2] = ModeratorRole   : allow if { input.operation == "moderate" }
//     RT.ids[3] = ObserverRole    : allow if { input.operation == "view" }
//     RT.ids[4..13]               : allow if { true }  (默认放行)
//
//   域策略（DomainTests 中创建，按 DT.ids 顺序）:
//     DT.ids[0] = GlobalScope        : allow if { input.resource.global == true }
//     DT.ids[1] = AsiaPacific        : allow if { input.resource.region == "asia" }
//     DT.ids[2] = NorthAmerica       : allow if { input.resource.region == "na" }
//     DT.ids[3] = SandboxEnvironment : allow if { input.resource.env == "sandbox" }
//     DT.ids[4..13]                  : allow if { true }  (默认放行)
//
//   群组嵌套结构（GroupTests/RelationTests 中建立，via move API + group_paths）:
//     GT.ids[0] (AdministratorGroup)
//         ├─ GT.ids[6]  (SalesTeam)        ← 继承 domain0 (GlobalScope)
//         └─ GT.ids[7]  (MarketingTeam)    ← 继承 domain0 (GlobalScope)
//     GT.ids[1] (OperatorGroup)
//         └─ GT.ids[8]  (HumanResources)   ← 继承 domain1 (AsiaPacific)
//     GT.ids[2] (DeveloperHub)
//         ├─ GT.ids[9]  (QualityAssurance) ← 继承 domain2 (NorthAmerica)
//         └─ GT.ids[10] (Designers)        ← 继承 domain2 (NorthAmerica)
//
//   群组-域绑定（RelationTests 中建立）:
//     GT.ids[0] (AdministratorGroup) <- DT.ids[0] (GlobalScope)
//     GT.ids[1] (OperatorGroup)      <- DT.ids[1] (AsiaPacific)
//     GT.ids[2] (DeveloperHub)       <- DT.ids[2] (NorthAmerica)
//     GT.ids[3] (BannedUsers)        <- DT.ids[3] (SandboxEnvironment)
//     GT.ids[6] (SalesTeam)          <- DT.ids[4] (default, allow if {true})
//     GT.ids[7] (MarketingTeam)      <- DT.ids[4] (default, allow if {true})
//
//   用户-群组成员（RelationTests 中建立）:
//     AT.ids[0] -> [GT.ids[0]]            // 单域 AND 场景
//     AT.ids[1] -> [GT.ids[1]]            // 单域 AND 场景
//     AT.ids[2] -> [GT.ids[2]]            // 单域 AND 场景
//     AT.ids[3] -> [GT.ids[0], GT.ids[3]] // 双群组域 + 用户直接域 AND 场景
//     AT.ids[4] -> []                     // 无 group，但有用户直接域
//     AT.ids[5] -> [GT.ids[0..3]]         // 四域 AND 场景
//     AT.ids[6] -> [GT.ids[6], GT.ids[7]] // 子群组用户，继承父群组域权限
//     AT.ids[7] -> [GT.ids[8], GT.ids[9]] // 多子群组用户，继承不同父群组域权限
//     AT.ids[8] -> [GT.ids[10]]           // 单子群组用户，继承父群组域权限
//
//   组内角色指派（RelationTests 中建立）:
//     RT.ids[3] (ObserverRole) -> AT.ids[0] in GT.ids[0]
//     RT.ids[4] (SalesManager) -> AT.ids[6] in GT.ids[6]
//     RT.ids[5] (HRLead)       -> AT.ids[7] in GT.ids[8]
//
//   用户被直接赋予的域权限:
//     AT.ids[0] <- DT.ids[0] (GlobalScope)
//     AT.ids[3] <- DT.ids[4] (Europe, default allow)
//     AT.ids[4] <- DT.ids[6] + DT.ids[7] (default allow)
//     AT.ids[5] <- DT.ids[8] + DT.ids[9] (default allow)
//
//   【鉴权逻辑】: judge() 先要求传入 role 对 user 可用；
//               最终结果 = role策略 AND 所属/父群组域策略 AND 用户直接域策略 AND 资源权限
//               嵌套群组时，父群组的域策略同样作用于用户
//
// =============================================================================


@Suite("权限策略 测试集", .serialized, .enabled(if: TestingShared.dbListening && TestingShared.opaListening))
struct PolicyTesting {

    @Test("开始测试")
    func start() async throws {
        while await TestingShared.testStage != .policy {
            try await Task.sleep(nanoseconds: 250_000_000)
        }
    }

    // =========================================================================
    // MARK: - Helpers
    // =========================================================================

    /// 通过 AT.ids[index] 精确查询用户，并 eager-load groups 关系。
    /// judge() 内部直接访问 user.model.groups（内存缓存），必须预加载。
    private func fetchUser(index: Int, s: PrivilegeSystem) async throws -> QUser {
        let model = try await __SDBM.User.query(on: s.pgDB)
            .filter(\.$id == AT.ids[index])
            .with(\.$groups)
            .first()
            
        return try QUser.make(from: try #require(model)).get()
    }

    /// 通过 RT.ids[index] 精确查询角色（策略写入 OPA 时用的就是这个 ID）。
    private func fetchRole(index: Int, s: PrivilegeSystem) async throws -> QRole {
        try #require(
            try await s.origin.query(QRole.self)
                .filter(\.id == RT.ids[index])
                .first()
        )
    }
    
    /// 通过 RT.ids[index] 精确查询角色策略（策略写入 OPA 时用的就是这个 ID）。
    private func fetchRolePolicy(index: Int, s: PrivilegeSystem) async throws -> [QPolicy<Role>] {
        try await s.origin.query(QPolicy<Role>.self)
            .filter(\.id ~~ RT.policyIds[index])
            .all()
    }
    
    /// 通过 RT.ids[index] 精确查询域策略（策略写入 OPA 时用的就是这个 ID）。
    private func fetchDomainPolicy(index: Int, s: PrivilegeSystem) async throws -> [QPolicy<Domain>] {
        try await s.origin.query(QPolicy<Domain>.self)
            .filter(\.id ~~ DT.policyIds[index])
            .all()
    }

    // =========================================================================
    // MARK: 3. 纯角色判定（AT.ids[4] 可用角色验证）
    // =========================================================================
    // user4 直接用户角色 = [RT[6], RT[7]]（均为 allow if {true}）
    // user4 直接用户域 = [domain6, domain7]（均为 allow if {true}）
    // userInGroups[4] = []（无 group）
    // 注意：user4 虽无 group，但有直接赋予的用户域，judge 时 domain reports 不为空！
    // 命名角色（SuperAdmin/Editor/Moderator/Observer）在 MARK 4-5 中与域策略一同验证

    
    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 4
    // Target Role: 6         [ Available ]
    // --------------------------------------------------
    // Inherit Group:None (Direct Mode)
    // --------------------------------------------------
    // Active Role: Role-6    ➔  allow if { true }
    // Bound Domain:Domain-6  ➔  allow if { true }
    // Bound Domain:Domain-7  ➔  allow if { true }
    // ==================================================
    // allow
    @Test("纯角色判定：user4+RT[6]，role 通过，user 直接域(domain6/domain7)也通过")
    func judgeRoleOnly_User4_Allow() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user4: 直接用户角色 RT[6]/RT[7]，直接用户域 domain6/domain7
        // domain6/domain7 均为 allow if {true}，空 resource 也能通过
        let user = try await fetchUser(index: 4, s: s)
        let role = try await fetchRole(index: 6, s: s) // RT[6]: allow if {true}

        let resource = JsonResource(appId: "test1", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.anything), privilegeIds: []
        )

        #expect(res.result, "RT[6](allow all) + domain6/7(allow all) → ALLOW")
        // user4 有直接赋予的 domain6, domain7，所以有 domain 报告
        let domainReports = res.reports.filter { $0.key.type == .domain }
        #expect(!domainReports.isEmpty, "user4 有直接赋予的 domain6/domain7，应有 domain 报告")
        #expect(domainReports.count == 2, "domain6 和 domain7 共 2 个 domain 报告")
        #expect(domainReports.values.allSatisfy { $0 }, "domain6/domain7 均 allow if {true} → 全 true")
        try #require(res.reports.count == 3)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[2].key.type == .domain)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 4
    // Target Role: 7         [ Available ]
    // --------------------------------------------------
    // Inherit Group:None (Direct Mode)
    // --------------------------------------------------
    // Active Role: Role-7    ➔  allow if { true }
    // Bound Domain:Domain-6  ➔  allow if { true }
    // Bound Domain:Domain-7  ➔  allow if { true }
    // ==================================================
    // allow
    @Test("纯角色判定：user4 使用 RT[7]，reports 结构验证（含用户直接域）")
    func judgeRoleOnly_User4_ReportsStructure() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user4: 直接用户角色 RT[6]/RT[7]，直接用户域 domain6/domain7
        let user = try await fetchUser(index: 4, s: s)
        let role = try await fetchRole(index: 7, s: s) // RT[7]: allow if {true}
        let rolePolicy = try #require(try await fetchRolePolicy(index: 7, s: s).first)

        let resource = JsonResource(appId: "test2", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(res.result, "RT[7](allow all) + domain6/7(allow all) → ALLOW")
        let roleKey = PrivilegeSystem.Arbitrator.Result.IdKey(type: .role, moduleId: m.moduleId, modelId: role.id, policyId: rolePolicy.id)
        #expect(res.reports[roleKey] == true, "role 报告应为 true")
        // user4 有直接赋予的 domain6, domain7，无 group
        let domainReports = res.reports.filter { $0.key.type == .domain }
        #expect(domainReports.count == 2, "user4 有 domain6 和 domain7 共 2 个直接域报告")
        try #require(res.reports.count == 3)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[2].key.type == .domain)
    }
    
    // SuperAdminRole 完整验证：user0 持有 RT[0]（用户角色），在 group0 中（domain0: global==true）
    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 0         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-0    ➔  allow if { input.operation == "manage_all" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // allow
    @Test("纯角色判定：SuperAdminRole(user0) manage_all+global=true → ALLOW")
    func judgeRoleOnly_SuperAdmin_Allowed() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user0 可用角色: RT[0](SuperAdmin 用户角色), RT[3](Observer 组内角色 in group0)
        // user0 在 group0，group0 绑 domain0(global==true)，需配合 global=true 使域通过
        let user = try await fetchUser(index: 0, s: s)
        let role = try await fetchRole(index: 0, s: s) // RT[0] = SuperAdminRole

        let resource = JsonResource(appId: "test3", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.manage_all), privilegeIds: []
        )
        #expect(res.result, "SuperAdminRole + manage_all + domain0(global=true) → ALLOW")
        try #require(res.reports.count == 2)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 0         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-0    ➔  allow if { input.operation == "manage_all" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // deny (operation != manage_all)
    // false, true
    @Test("纯角色判定：SuperAdminRole(user0) edit → DENY（role 策略不匹配）")
    func judgeRoleOnly_SuperAdmin_Denied() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 0, s: s)
        let role = try await fetchRole(index: 0, s: s)
        let rolePolicy = try #require(try await fetchRolePolicy(index: 0, s: s).first)

        let resource = JsonResource(appId: "test4", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.edit), privilegeIds: []
        )
        #expect(!res.result, "SuperAdminRole 不允许 edit → DENY")
        let roleKey = PrivilegeSystem.Arbitrator.Result.IdKey(type: .role, moduleId: m.moduleId, modelId: role.id, policyId: rolePolicy.id)
        #expect(res.reports[roleKey] == false)
        try #require(res.reports.count == 2)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[0].value == false)
        #expect(res.reports.elements[1].value == true)
    }

    // EditorRole 完整验证：user1 持有 RT[1]（用户角色），在 group1 中（domain1: region==asia）
    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 1
    // Target Role: 1         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-1
    // --------------------------------------------------
    // Active Role: Role-1    ➔  allow if { input.operation == "edit" } allow if { input.operation == "publish" }
    // Bound Domain:Domain-1  ➔  allow if { input.resource.region == "asia" }
    // ==================================================
    // 1: edit -> allow
    // 2: public -> allow
    // 3: deny -> false true
    @Test("纯角色判定：EditorRole(user1) edit+region=asia → ALLOW；manage_all → DENY")
    func judgeRoleOnly_Editor() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user1 可用角色: RT[1](Editor), RT[3](Observer)；在 group1，domain1(region=asia)
        let user = try await fetchUser(index: 1, s: s)
        let role = try await fetchRole(index: 1, s: s) // RT[1] = EditorRole

        for (i, op) in ["edit", "publish"].enumerated() {
            let resource = JsonResource(appId: "test5_\(i)", content: ["region": AnyCodable("asia")])
            let resourceDTO = try await m.resource.create(resources: [resource]).first!
            let res = try await s.arbitrator.judge(
                moduleId: m.moduleId, user: user, role: role,
                resource: try #require(GResource(resourceDTO)),
                operation: .init(op: JsonOperation(rawValue: op)!), privilegeIds: []
            )
            #expect(res.result, "EditorRole + \(op) + region=asia → ALLOW")
            try #require(res.reports.count == 2)
            #expect(res.reports.elements[0].key.type == .role)
            #expect(res.reports.elements[1].key.type == .domain)
        }

        let resource = JsonResource(appId: "test6", content: ["region": AnyCodable("asia")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let denied = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.manage_all), privilegeIds: []
        )
        #expect(!denied.result, "EditorRole 不允许 manage_all → DENY")
        try #require(denied.reports.count == 2)
        #expect(denied.reports.elements[0].key.type == .role)
        #expect(denied.reports.elements[1].key.type == .domain)
        #expect(denied.reports.elements[0].value == false)
        #expect(denied.reports.elements[1].value == true)
    }

    // ModeratorRole 完整验证：user2 持有 RT[2]，在 group2 中（domain2: region==na）
    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 2
    // Target Role: 2         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-2
    // --------------------------------------------------
    // Active Role: Role-2    ➔  allow if { input.operation == "moderate" }
    // Bound Domain:Domain-2  ➔  allow if { input.resource.region == "na" }
    // ==================================================
    // 1: allow
    // 2: deny -> false, true
    @Test("纯角色判定：ModeratorRole(user2) moderate+region=na → ALLOW；edit → DENY")
    func judgeRoleOnly_Moderator() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user2 可用角色: RT[2](Moderator)；在 group2，domain2(region=na)
        let user = try await fetchUser(index: 2, s: s)
        let role = try await fetchRole(index: 2, s: s)

        let resource = JsonResource(appId: "test7", content: ["region": AnyCodable("na")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.moderate), privilegeIds: []
        )
        #expect(allow.result, "ModeratorRole + moderate + region=na → ALLOW")
        try #require(allow.reports.count == 2)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)
        
        let resource2 = JsonResource(appId: "test8", content: ["region": AnyCodable("na")])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.edit), privilegeIds: []
        )
        #expect(!deny.result, "ModeratorRole 不允许 edit → DENY")
        try #require(deny.reports.count == 2)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[0].value == false)
        #expect(deny.reports.elements[1].value == true)
    }

    // ObserverRole 完整验证：user1 持有 RT[3]（用户角色），在 group1（domain1: region==asia）
    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 1
    // Target Role: 3         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-1
    // --------------------------------------------------
    // Active Role: Role-3    ➔  allow if { input.operation == "view" }
    // Bound Domain:Domain-1  ➔  allow if { input.resource.region == "asia" }
    // ==================================================
    // allow
    @Test("纯角色判定：ObserverRole(user1) view+region=asia → ALLOW，reports 结构验证")
    func judgeRoleOnly_Observer_ReportsStructure() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user1 可用角色: RT[1](Editor), RT[3](Observer)
        let user = try await fetchUser(index: 1, s: s)
        let role = try await fetchRole(index: 3, s: s) // RT[3] = ObserverRole
        let rolePolicy = try #require(try await fetchRolePolicy(index: 3, s: s).first)

        let resource = JsonResource(appId: "test9", content: ["region": AnyCodable("asia")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(res.result, "ObserverRole + view + region=asia → ALLOW")
        let roleKey = PrivilegeSystem.Arbitrator.Result.IdKey(type: .role, moduleId: m.moduleId, modelId: role.id, policyId: rolePolicy.id)
        #expect(res.reports[roleKey] == true, "role 报告应为 true")
        try #require(res.reports.count == 2)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
    }


    // =========================================================================
    // MARK: 4. 角色 + 单域 AND（AT.ids[0] -> GT.ids[0] -> DT.ids[0]: global==true）
    // =========================================================================

    // user0 可用角色：RT[0](SuperAdmin 用户角色) + RT[3](Observer 组内角色 in group0)
    // group0 绑 domain0: global==true

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 3         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-3    ➔  allow if { input.operation == "view" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // allow
    @Test("角色+单域：role(Observer) ✓ domain ✓ → ALLOW")
    func judgeRoleAndDomain_BothPass() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user0 → group0 → domain0(global==true)；RT[3](Observer) 是 user0 的组内角色
        let user = try await fetchUser(index: 0, s: s)
        let role = try await fetchRole(index: 3, s: s) // RT[3] = ObserverRole: view

        let resource = JsonResource(appId: "test10", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(res.result, "ObserverRole + domain0(global=true) + view → ALLOW")
        #expect(res.reports.filter { $0.key.type == .role }.values.allSatisfy { $0 })
        #expect(res.reports.filter { $0.key.type == .domain }.values.allSatisfy { $0 })
        try #require(res.reports.count == 2)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 3         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-3    ➔  allow if { input.operation == "view" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // deny -> true, false
    @Test("角色+单域：role(Observer) ✓ domain ✗ (global=false) → DENY")
    func judgeRoleAndDomain_DomainFails() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 0, s: s)
        let role = try await fetchRole(index: 3, s: s) // RT[3] ObserverRole

        let resource = JsonResource(appId: "test11", content: ["global": AnyCodable(false)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(!res.result, "domain0 要求 global==true，false 时 DENY")
        #expect(res.reports.filter { $0.key.type == .domain }.values.contains(false))
        try #require(res.reports.count == 2)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[0].value == true)
        #expect(res.reports.elements[1].value == false)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 0         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-0    ➔  allow if { input.operation == "manage_all" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // deny -> false, true
    @Test("角色+单域：role(SuperAdmin) ✗ (operation不匹配) domain ✓ → DENY")
    func judgeRoleAndDomain_RoleFails() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 0, s: s)
        let role = try await fetchRole(index: 0, s: s) // RT[0] = SuperAdminRole: manage_all only

        let resource = JsonResource(appId: "test12", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        // operation=view → SuperAdminRole 不允许 → role 失败；domain0(global=true) 通过
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(!res.result, "SuperAdminRole 不允许 view，domain 通过也应 DENY")
        #expect(res.reports.filter { $0.key.type == .role }.values.contains(false))
        try #require(res.reports.count == 2)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[0].value == false)
        #expect(res.reports.elements[1].value == true)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 0         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-0    ➔  allow if { input.operation == "manage_all" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // deny -> false, false
    @Test("角色+单域：role(SuperAdmin) ✗ domain ✗ → DENY")
    func judgeRoleAndDomain_BothFail() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 0, s: s)
        let role = try await fetchRole(index: 0, s: s)

        let resource = JsonResource(appId: "test13", content: ["global": AnyCodable(false)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(!res.result, "role(SuperAdmin+view) 和 domain(global=false) 均失败 → DENY")
        try #require(res.reports.count == 2)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[0].value == false)
        #expect(res.reports.elements[1].value == false)
    }

    // =========================================================================
    // MARK: 5. 不同单域策略验证
    // =========================================================================
    // user1 可用角色: RT[1](Editor), RT[3](Observer) —— 均为用户角色
    // user2 可用角色: RT[2](Moderator) —— 用户角色

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 1
    // Target Role: 3         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-1
    // --------------------------------------------------
    // Active Role: Role-3    ➔  allow if { input.operation == "view" }
    // Bound Domain:Domain-1  ➔  allow if { input.resource.region == "asia" }
    // ==================================================
    // 1: allow
    // 2: deny -> true, false
    @Test("AsiaPacific域(DT.ids[1])：region=asia 时允许，region=na 时拒绝")
    func judgeAsiaPacificDomain() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // AT.ids[1] -> GT.ids[1] -> DT.ids[1]: region=="asia"
        let user = try await fetchUser(index: 1, s: s)
        let role = try await fetchRole(index: 3, s: s) // RT[3] = ObserverRole: view (user1 用户角色)

        let resource = JsonResource(appId: "test14", content: ["region": AnyCodable("asia")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(allow.result, "region=asia → AsiaPacific 域通过 → ALLOW")
        try #require(allow.reports.count == 2)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)

        let resource2 = JsonResource(appId: "test15", content: ["region": AnyCodable("na")])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(!deny.result, "region=na → AsiaPacific 域失败 → DENY")
        try #require(deny.reports.count == 2)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == false)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 2
    // Target Role: 2         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-2
    // --------------------------------------------------
    // Active Role: Role-2    ➔  allow if { input.operation == "moderate" }
    // Bound Domain:Domain-2  ➔  allow if { input.resource.region == "na" }
    // ==================================================
    // 1: allow
    // 2: deny -> true, false
    @Test("NorthAmerica域(DT.ids[2])：region=na 时允许，region=asia 时拒绝")
    func judgeNorthAmericaDomain() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // AT.ids[2] -> GT.ids[2] -> DT.ids[2]: region=="na"
        let user = try await fetchUser(index: 2, s: s)
        let role = try await fetchRole(index: 2, s: s) // RT[2] = ModeratorRole: moderate (user2 用户角色)

        let resource = JsonResource(appId: "test16", content: ["region": AnyCodable("na")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.moderate), privilegeIds: []
        )
        #expect(allow.result, "region=na → NorthAmerica 域通过 → ALLOW")
        try #require(allow.reports.count == 2)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)

        let resource2 = JsonResource(appId: "test17", content: ["region": AnyCodable("asia")])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.moderate), privilegeIds: []
        )
        #expect(!deny.result, "region=asia → NorthAmerica 域失败 → DENY")
        try #require(deny.reports.count == 2)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == false)
    }

    // =========================================================================
    // MARK: 6. 双域 AND（AT.ids[3] -> GT.ids[0]+GT.ids[3] -> domain0+domain3）
    // =========================================================================
    // domain0: global==true，domain3: env==sandbox
    // user3 可用角色: RT[4](用户角色, allow if {true}), RT[5](群组角色 via group3, allow if {true})

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 3
    // Target Role: 4         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-3
    // --------------------------------------------------
    // Active Role: Role-4    ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-3  ➔  allow if { input.resource.env == "sandbox" }
    // Bound Domain:Domain-4  ➔  allow if { true }
    // ==================================================
    // allow
    @Test("双域AND：全部满足 → ALLOW，reports 包含 3 个域")
    func judgeMultiDomain_AllPass() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user3: userInGroups[3]=[0,3] → group0(domain0: global==true) + group3(domain3: env==sandbox)
        // 同时直接赋予 domain4(allow if {true})
        // 因此 domain reports 共 3 个: domain0 + domain3 + domain4
        let user = try await fetchUser(index: 3, s: s)
        let role = try await fetchRole(index: 4, s: s) // RT[4]: allow if {true}（user3 的用户角色）

        let resource = JsonResource(appId: "test18", content: ["global": AnyCodable(true), "env": AnyCodable("sandbox")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(res.result, "role+domain0+domain3+domain4 全通过 → ALLOW")
        let domainReports = res.reports.filter { $0.key.type == .domain }
        #expect(domainReports.count == 3, "应有 3 个域报告: domain0(群组)+domain3(群组)+domain4(用户直接)")
        #expect(domainReports.values.allSatisfy { $0 })
        try #require(res.reports.count == 4)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[2].key.type == .domain)
        #expect(res.reports.elements[3].key.type == .domain)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 3
    // Target Role: 4         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-3
    // --------------------------------------------------
    // Active Role: Role-4    ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-3  ➔  allow if { input.resource.env == "sandbox" }
    // Bound Domain:Domain-4  ➔  allow if { true }
    // ==================================================
    // deny: true, true, false, true
    @Test("双域AND：domain3(env==sandbox)不满足 → DENY")
    func judgeMultiDomain_Domain3Fails() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 3, s: s)
        let role = try await fetchRole(index: 4, s: s) // RT[4]: allow if {true}

        let resource = JsonResource(appId: "test19", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(!res.result, "domain3 要求 env==sandbox，缺失 → DENY")
        #expect(res.reports.filter { $0.key.type == .domain }.values.contains(false))
        try #require(res.reports.count == 4)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[2].key.type == .domain)
        #expect(res.reports.elements[3].key.type == .domain)
        #expect(res.reports.elements[0].value == true)
        #expect(res.reports.elements[1].value == true)
        #expect(res.reports.elements[2].value == false)
        #expect(res.reports.elements[3].value == true)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 3
    // Target Role: 5         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-3
    // --------------------------------------------------
    // Active Role: Role-5    ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-3  ➔  allow if { input.resource.env == "sandbox" }
    // Bound Domain:Domain-4  ➔  allow if { true }
    // ==================================================
    // deny: true false true true
    @Test("双域AND：domain0(global==true)不满足 → DENY")
    func judgeMultiDomain_Domain0Fails() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 3, s: s)
        let role = try await fetchRole(index: 5, s: s) // RT[5]: 群组角色，allow if {true}

        let resource = JsonResource(appId: "test20", content: ["env": AnyCodable("sandbox")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(!res.result, "domain0 要求 global==true，缺失 → DENY")
        try #require(res.reports.count == 4)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[2].key.type == .domain)
        #expect(res.reports.elements[3].key.type == .domain)
        #expect(res.reports.elements[0].value == true)
        #expect(res.reports.elements[1].value == false)
        #expect(res.reports.elements[2].value == true)
        #expect(res.reports.elements[3].value == true)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 3
    // Target Role: 5         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-3
    // --------------------------------------------------
    // Active Role: Role-5    ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-3  ➔  allow if { input.resource.env == "sandbox" }
    // Bound Domain:Domain-4  ➔  allow if { true }
    // ==================================================
    // deny -> true false, false, true
    @Test("双域AND：两个群组域均不满足 → DENY（但 domain4 直接域仍通过）")
    func judgeMultiDomain_BothFail() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user3 域: group0(domain0: global==true) + group3(domain3: env==sandbox) + 直接 domain4(allow all)
        // 传空 resource：domain0失败, domain3失败, domain4通过
        // AND 逻辑下，任一失败则整体 DENY
        let user = try await fetchUser(index: 3, s: s)
        let role = try await fetchRole(index: 4, s: s)

        let resource = JsonResource(appId: "test21", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(!res.result, "domain0/domain3 均失败 → 整体 DENY（即使 domain4 通过）")
        // domain4(allow all) 为 true，所以不能断言所有域均为 false
        let domainReports = res.reports.filter { $0.key.type == .domain }
        #expect(domainReports.values.contains(false), "至少 domain0 或 domain3 不满足 → 应包含 false")
        try #require(res.reports.count == 4)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[2].key.type == .domain)
        #expect(res.reports.elements[3].key.type == .domain)
        #expect(res.reports.elements[0].value == true)
        #expect(res.reports.elements[1].value == false)
        #expect(res.reports.elements[2].value == false)
        #expect(res.reports.elements[3].value == true)
    }

    // =========================================================================
    // MARK: 7. 四域极端 AND（AT.ids[5] -> domain0,1,2,3）
    // =========================================================================
    // user5 直接用户角色 = [RT[8],RT[9]]
    // userInGroups[5]=[0,1,2,3] → group0(domain0) + group1(domain1) + group2(domain2) + group3(domain3)
    // user5 直接用户域 = [domain8,domain9] (均 allow if {true})
    // domain reports 共 6 个: domain0~3(群组) + domain8,9(用户直接)
    // domain1(asia) 和 domain2(na) 互斥，region 不能同时满足，验证 AND 严格性

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 5
    // Target Role: 8         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-1
    // Inherit Group:Group-2
    // Inherit Group:Group-3
    // --------------------------------------------------
    // Active Role: Role-8    ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-1  ➔  allow if { input.resource.region == "asia" }
    // Bound Domain:Domain-2  ➔  allow if { input.resource.region == "na" }
    // Bound Domain:Domain-3  ➔  allow if { input.resource.env == "sandbox" }
    // Bound Domain:Domain-8  ➔  allow if { true }
    // Bound Domain:Domain-9  ➔  allow if { true }
    // ==================================================
    // deny: true, true, true, false, true, true, true
    @Test("四域极端AND：domain1(asia)与domain2(na)互斥 → 始终 DENY")
    func judgeQuadDomain_AlwaysDeny() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user5: 直接用户角色 RT[8]/RT[9]，全部为 allow if {true}
        // user5 在 group0~3 + 直接域 domain8/9，共 6 个 domain
        let user = try await fetchUser(index: 5, s: s)
        let role = try await fetchRole(index: 8, s: s) // RT[8]: allow if {true}

        let resource = JsonResource(appId: "test22", content: [
            "global": AnyCodable(true),
            "env": AnyCodable("sandbox"),
            "region": AnyCodable("asia") // domain2 需要 na，并预 asia → domain2 失败
        ])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(!res.result, "domain2 需要 region=na，与 domain1 的 asia 互斥 → 始终 DENY")
        let domainReports = res.reports.filter { $0.key.type == .domain }
        // user5 有 6 个 domain：domain0(群组)+domain1(群组)+domain2(群组)+domain3(群组)+domain8(直接)+domain9(直接)
        #expect(domainReports.count == 6, "6 个 domain: 4 个群组域 + 2 个用户直接域")
        #expect(domainReports.values.contains(false), "domain2(na)与 domain1(asia)互斥 → 应有 false")
        try #require(res.reports.count == 7)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[2].key.type == .domain)
        #expect(res.reports.elements[3].key.type == .domain)
        #expect(res.reports.elements[4].key.type == .domain)
        #expect(res.reports.elements[5].key.type == .domain)
        #expect(res.reports.elements[6].key.type == .domain)
        #expect(res.reports.elements[0].value == true)
        #expect(res.reports.elements[1].value == true)
        #expect(res.reports.elements[2].value == true)
        #expect(res.reports.elements[3].value == false)
        #expect(res.reports.elements[4].value == true)
        #expect(res.reports.elements[5].value == true)
        #expect(res.reports.elements[6].value == true)
    }

    // =========================================================================
    // MARK: 8. 组内角色指派场景（RT.ids[3] -> AT.ids[0] in GT.ids[0]）
    // =========================================================================

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 3         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-3    ➔  allow if { input.operation == "view" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // 1: allow
    // 2: deny -> true, false
    @Test("组内角色指派：ObserverRole + domain0(global==true) 满足 → ALLOW")
    func judgeInGroupRole_Allow() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // AT.ids[0] 在 GT.ids[0] 中，RT.ids[3](ObserverRole) 已通过 roleForGroupUser 指派
        let user = try await fetchUser(index: 0, s: s)
        let role = try await fetchRole(index: 3, s: s)

        let resource = JsonResource(appId: "test23", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(allow.result, "ObserverRole + domain0 全满足 → ALLOW")
        try #require(allow.reports.count == 2)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)

        let resource2 = JsonResource(appId: "test24", content: ["global": AnyCodable(false)])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(!deny.result, "global=false → domain0 失败 → DENY")
        try #require(deny.reports.count == 2)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == false)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 0         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-0    ➔  allow if { input.operation == "manage_all" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // deny -> false, true
    @Test("组内角色指派：使用不匹配的 role → DENY（role 策略不通过）")
    func judgeInGroupRole_WrongRole() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 0, s: s)
        let role = try await fetchRole(index: 0, s: s)  // SuperAdminRole: manage_all only

        let resource = JsonResource(appId: "test25", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.edit), privilegeIds: []
        )

        #expect(!res.result, "SuperAdminRole 不允许 edit，domain 通过也 DENY")
        try #require(res.reports.count == 2)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[0].value == false)
        #expect(res.reports.elements[1].value == true)
    }

    // =========================================================================
    // MARK: 9. 策略语义变更与仲裁
    // =========================================================================

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 8
    // Target Role: 12        [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-2
    // Inherit Group:Group-10
    // --------------------------------------------------
    // Active Role: Role-12   ➔  allow if { true }
    // Bound Domain:Domain-2  ➔  allow if { input.resource.region == "na" }
    // ==================================================
    // 1: allow
    @Test("Role 策略替换：新语义立即影响仲裁结果（deploy 限制）")
    func rolePolicy_ReplaceAndRejudge() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // 使用 RT.ids[12](ContentReviewer)，属于 user8(用户角色)
        // group10 属于 group2(DeveloperHub, domain2: region=na) 的子群组
        //      所以初始 judge 需要 region=na 来满足 domain2
        let targetId = RT.ids[12]
        let user = try await fetchUser(index: 8, s: s)
        let role = try await fetchRole(index: 12, s: s) // RT[12] = user8 的用户角色

        let resource = JsonResource(appId: "test26", content: ["region": AnyCodable("na")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        // 替换前：allow if { true } → 任何操作都通过（配合 region=na 满足域策略）
        let before = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.anything), privilegeIds: []
        )
        #expect(before.result, "替换前默认策略允许任何操作")
        try #require(before.reports.count == 2)
        #expect(before.reports.elements[0].key.type == .role)
        #expect(before.reports.elements[1].key.type == .domain)
        
        // 删除旧策略
        let old = try await __SDBM.PolicyExp<Role>.query(on: s.pgDB)
            .filter(\.$parent.$id == targetId).all()
        for p in old {
            let qp = try QPolicy<Role>.make(from: p).get()
            try await s.policy.delete(from: Role.self, policy: qp => targetId)
        }

        // 写入新策略：只允许 deploy
        let restricted = PPolicy<Role>(
            moduleId: m.moduleId,
            policy: "allow if { input.operation == \"deploy\" }"
        )
        try await s.policy.create(to: Role.self) { OrderedSet([restricted]) => targetId }

        // 验证新策略
        let deployRes = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.deploy), privilegeIds: []
        )
        #expect(deployRes.result, "替换后：deploy → ALLOW")
        
        let denyRes = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.anything), privilegeIds: []
        )
        #expect(!denyRes.result, "替换后：anything → DENY")

        // 清理并恢复
        let newPolicies = try await __SDBM.PolicyExp<Role>.query(on: s.pgDB)
            .filter(\.$parent.$id == targetId).all()
        for p in newPolicies {
            let qp = try QPolicy<Role>.make(from: p).get()
            try await s.policy.delete(from: Role.self, policy: qp => targetId)
        }
        let def = PPolicy<Role>(moduleId: m.moduleId, policy: "allow if { true }")
        try await s.policy.create(to: Role.self) { OrderedSet([def]) => targetId }
    }


    // =========================================================================
    // MARK: 10. 综合场景
    // =========================================================================

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 1
    // Target Role: 1         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-1
    // --------------------------------------------------
    // Active Role: Role-1    ➔  allow if { input.operation == "edit" } allow if { input.operation == "publish" }
    // Bound Domain:Domain-1  ➔  allow if { input.resource.region == "asia" }
    // ==================================================
    // 1: allow
    // 2: deny -> true, false
    // 3: deny -> false, true
    @Test("综合：EditorRole + AsiaPacific域，正确地区可编辑，错误地区被拒")
    func comprehensive_EditorInAsiaPacific() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // AT.ids[1] -> GT.ids[1] -> DT.ids[1]: region=="asia"
        // RT.ids[1] = EditorRole：edit/publish
        let user = try await fetchUser(index: 1, s: s)
        let role = try await fetchRole(index: 1, s: s)

        let resource = JsonResource(appId: "test27", content: ["region": AnyCodable("asia")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        // ✓ 亚太地区 + edit
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.edit), privilegeIds: []
        )
        #expect(allow.result, "EditorRole + region=asia → ALLOW")
        try #require(allow.reports.count == 2)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)

        let resource2 = JsonResource(appId: "test28", content: ["region": AnyCodable("eu")])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        // ✗ 欧洲地区 + publish（region 不匹配 domain1）
        let denyRegion = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.publish), privilegeIds: []
        )
        #expect(!denyRegion.result, "region=eu → AsiaPacific 域失败 → DENY")
        try #require(denyRegion.reports.count == 2)
        #expect(denyRegion.reports.elements[0].key.type == .role)
        #expect(denyRegion.reports.elements[1].key.type == .domain)
        #expect(denyRegion.reports.elements[0].value == true)
        #expect(denyRegion.reports.elements[1].value == false)

        let resource3 = JsonResource(appId: "test29", content: ["region": AnyCodable("asia")])
        let resourceDTO3 = try await m.resource.create(resources: [resource3]).first!
        
        // ✗ 正确地区但无权操作
        let denyOp = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO3)),
            operation: .init(op: JsonOperation.manage_all), privilegeIds: []
        )
        #expect(!denyOp.result, "EditorRole 不允许 manage_all → DENY")
        try #require(denyOp.reports.count == 2)
        #expect(denyOp.reports.elements[0].key.type == .role)
        #expect(denyOp.reports.elements[1].key.type == .domain)
        #expect(denyOp.reports.elements[0].value == false)
        #expect(denyOp.reports.elements[1].value == true)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 2
    // Target Role: 2         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-2
    // --------------------------------------------------
    // Active Role: Role-2    ➔  allow if { input.operation == "moderate" }
    // Bound Domain:Domain-2  ➔  allow if { input.resource.region == "na" }
    // ==================================================
    // 1: allow
    // 2: deny -> true, false
    // 3: deny -> false, true
    @Test("综合：ModeratorRole + NorthAmerica域，跨域操作被隔离")
    func comprehensive_ModeratorInNorthAmerica() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // AT.ids[2] -> GT.ids[2] -> DT.ids[2]: region=="na"
        let user = try await fetchUser(index: 2, s: s)
        let role = try await fetchRole(index: 2, s: s)  // ModeratorRole: moderate

        let resource = JsonResource(appId: "test30", content: ["region": AnyCodable("na")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.moderate), privilegeIds: []
        )
        #expect(allow.result, "ModeratorRole + region=na → ALLOW")
        try #require(allow.reports.count == 2)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)

        let resource2 = JsonResource(appId: "test31", content: ["region": AnyCodable("asia")])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        let denyAsia = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.moderate), privilegeIds: []
        )
        #expect(!denyAsia.result, "region=asia → NorthAmerica 域失败 → DENY")
        try #require(denyAsia.reports.count == 2)
        #expect(denyAsia.reports.elements[0].key.type == .role)
        #expect(denyAsia.reports.elements[1].key.type == .domain)
        #expect(denyAsia.reports.elements[0].value == true)
        #expect(denyAsia.reports.elements[1].value == false)

        let denyEdit = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.edit), privilegeIds: []
        )
        #expect(!denyEdit.result, "ModeratorRole 不允许 edit → DENY")
        try #require(denyEdit.reports.count == 2)
        #expect(denyEdit.reports.elements[0].key.type == .role)
        #expect(denyEdit.reports.elements[1].key.type == .domain)
        #expect(denyEdit.reports.elements[0].value == false)
        #expect(denyEdit.reports.elements[1].value == true)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 3
    // Target Role: 4         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-3
    // --------------------------------------------------
    // Active Role: Role-4    ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-3  ➔  allow if { input.resource.env == "sandbox" }
    // Bound Domain:Domain-4  ➔  allow if { true }
    // ==================================================
    // 1: allow
    // 2: deny -> true, false, true, true
    // 3: deny -> true, true, false, true
    // 4: deny -> true, false, false, true
    @Test("综合：RT[4](默认放行) + GlobalScope+Sandbox 双域，精准访问控制矩阵")
    func comprehensive_ObserverTwoDomains() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // AT.ids[3] → GT.ids[0](domain0: global==true) + GT.ids[3](domain3: env==sandbox)
        // user3 可用角色: RT[4](用户角色, allow if {true}), RT[5](群组角色 via group3)
        let user = try await fetchUser(index: 3, s: s)
        let role = try await fetchRole(index: 4, s: s) // RT[4]: allow if {true}

        struct Case {
            let resource: JsonResource
            let op: JsonOperation
            let expected: Bool
            let desc: String
        }

        let cases: [Case] = [
            .init(resource: JsonResource(appId: "test32", content: ["global": AnyCodable(true), "env": AnyCodable("sandbox")]),
                  op: .view, expected: true,   desc: "双域全满足 + view → ALLOW"),
            .init(resource: JsonResource(appId: "test33", content: ["global": AnyCodable(false), "env": AnyCodable("sandbox")]),
                  op: .view, expected: false,  desc: "global=false → domain0 失败 → DENY"),
            .init(resource: JsonResource(appId: "test34", content: ["global": AnyCodable(true)]),
                  op: .view, expected: false,  desc: "env 缺失 → domain3 失败 → DENY"),
            .init(resource: JsonResource(appId: "test35", content: [:]), op: .view, expected: false, desc: "两域均失败 → DENY")
        ]

        for c in cases {
            let resourceDTO = try await m.resource.create(resources: [c.resource]).first!
            
            let res = try await s.arbitrator.judge(
                moduleId: m.moduleId, user: user, role: role,
                resource: try #require(GResource(resourceDTO)),
                operation: .init(op: c.op), privilegeIds: []
            )
            if res.result != c.expected {
                Issue.record("场景「\(c.desc)」期望 \(c.expected)，实际 \(res.result)")
            }
        }
    }

    // =========================================================================
    // MARK: 11. 边界场景
    // =========================================================================

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 4
    // Target Role: 6         [ Available ]
    // --------------------------------------------------
    // Inherit Group:None (Direct Mode)
    // --------------------------------------------------
    // Active Role: Role-6    ➔  allow if { true }
    // Bound Domain:Domain-6  ➔  allow if { true }
    // Bound Domain:Domain-7  ➔  allow if { true }
    // ==================================================
    // allow
    @Test("边界：空 privilegeIds 不影响纯角色鉴权")
    func edge_EmptyPrivilegeIds() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user4 可用角色: RT[6], RT[7](均为 allow if {true})
        let user = try await fetchUser(index: 4, s: s)
        let role = try await fetchRole(index: 6, s: s) // RT[6]: allow if {true}

        let resource = JsonResource(appId: "test36", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.anything), privilegeIds: []
        )
        #expect(res.result, "空 privilegeIds 不影响纯角色鉴权")
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 4
    // Target Role: 6         [ Available ]
    // --------------------------------------------------
    // Inherit Group:None (Direct Mode)
    // --------------------------------------------------
    // Active Role: Role-6    ➔  allow if { true }
    // Bound Domain:Domain-6  ➔  allow if { true }
    // Bound Domain:Domain-7  ➔  allow if { true }
    // Resource:              ➔  allow if { input.operation == "read" }
    // ==================================================
    // 1: allow
    // 2: deny -> true, true, true, false
    @Test("资源权限：privilegeIds 非空时，privilege 策略参与最终 AND")
    func edge_PrivilegePolicyParticipatesInAnd() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 4, s: s)
        let role = try await fetchRole(index: 6, s: s) // RT[6]: allow if {true}
        let suffix = UUID().uuidString

        let privileges = try await m.privilege.createWithReturning(privileges: [
            .init(
                name: "PolicyTestReadPrivilege-\(suffix)",
                summary: "PolicyTests 临时资源权限",
                policy: "allow if { input.operation == \"read\" }"
            )
        ])
        let privilege = try #require(privileges.first)

        let resource = JsonResource(appId: "test37", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.read), privilegeIds: [privilege.id]
        )
        #expect(allow.result, "role/domain/privilege 均通过 → ALLOW")
        try #require(allow.reports.count == 4)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)
        #expect(allow.reports.elements[2].key.type == .domain)
        #expect(allow.reports.elements[3].key.type == .privilege)

        let privilegeKey = PrivilegeSystem.Arbitrator.Result.IdKey(
            type: .privilege, moduleId: m.moduleId, modelId: nil, policyId: privilege.id
        )
        #expect(allow.reports[privilegeKey] == true, "privilege 报告应为 true")

        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.write), privilegeIds: [privilege.id]
        )
        #expect(!deny.result, "privilege 不允许 write → 整体 DENY")
        #expect(deny.reports[privilegeKey] == false, "privilege 报告应为 false")
        try #require(deny.reports.count == 4)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[2].key.type == .domain)
        #expect(deny.reports.elements[3].key.type == .privilege)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == true)
        #expect(deny.reports.elements[2].value == true)
        #expect(deny.reports.elements[3].value == false)

        try await m.privilege.delete(policy: privilege)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 4
    // Target Role: 6         [ Available ]
    // --------------------------------------------------
    // Inherit Group:None (Direct Mode)
    // --------------------------------------------------
    // Active Role: Role-6    ➔  allow if { true }
    // Bound Domain:Domain-6  ➔  allow if { true }
    // Bound Domain:Domain-7  ➔  allow if { true }
    // Resource:              ➔  allow if { input.operation == "read" }
    // Resource:              ➔  allow if { input.resource.kind == "file" }
    // ==================================================
    // 1: allow
    // 2: deny -> true, true, true, false, true
    // 3: deny -> true, true, true, true, false
    @Test("资源权限：多个 privilegeIds 必须全部通过，reports 分别记录")
    func edge_MultiplePrivilegePoliciesAreAnded() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 4, s: s)
        let role = try await fetchRole(index: 6, s: s) // RT[6]: allow if {true}
        let suffix = UUID().uuidString

        let privileges = try await m.privilege.createWithReturning(privileges: [
            .init(
                name: "PolicyTestReadPrivilege-\(suffix)",
                summary: "PolicyTests 临时 read 权限",
                policy: "allow if { input.operation == \"read\" }"
            ),
            .init(
                name: "PolicyTestFilePrivilege-\(suffix)",
                summary: "PolicyTests 临时 file 权限",
                policy: "allow if { input.resource.kind == \"file\" }"
            )
        ])
        let readPrivilege = try #require(privileges.first)
        let filePrivilege = try #require(privileges.dropFirst().first)
        let readKey = PrivilegeSystem.Arbitrator.Result.IdKey(
            type: .privilege, moduleId: m.moduleId, modelId: nil, policyId: readPrivilege.id
        )
        let fileKey = PrivilegeSystem.Arbitrator.Result.IdKey(
            type: .privilege, moduleId: m.moduleId, modelId: nil, policyId: filePrivilege.id
        )
        
        let resource = JsonResource(appId: "test38", content: ["kind": AnyCodable("file")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!

        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.read), privilegeIds: [readPrivilege.id, filePrivilege.id]
        )
        #expect(allow.result, "两个 privilege 均通过 → ALLOW")
        #expect(allow.reports[readKey] == true)
        #expect(allow.reports[fileKey] == true)

        let denyOperation = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.write), privilegeIds: [readPrivilege.id, filePrivilege.id]
        )
        #expect(!denyOperation.result, "read privilege 失败 → 整体 DENY")
        #expect(denyOperation.reports[readKey] == false)
        #expect(denyOperation.reports[fileKey] == true)

        let resource2 = JsonResource(appId: "test39", content: ["kind": AnyCodable("directory")])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        let denyResource = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.read), privilegeIds: [readPrivilege.id, filePrivilege.id]
        )
        #expect(!denyResource.result, "file privilege 失败 → 整体 DENY")
        #expect(denyResource.reports[readKey] == true)
        #expect(denyResource.reports[fileKey] == false)

        for privilege in privileges {
            try await m.privilege.delete(policy: privilege)
        }
    }

    @Test("混合权限仲裁：使用 userId 和 roleId 执行仲裁")
    func edge_ArbitrateWithUserIdAndRoleId() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 4, s: s)
        let role = try await fetchRole(index: 6, s: s)
        let suffix = UUID().uuidString
        
        let privileges = try await m.privilege.createWithReturning(privileges: [
            .init(
                name: "UserIdArbitrateTest-\(suffix)",
                policy: "allow if { input.operation == \"read\" }"
            )
        ])
        let privilege = try #require(privileges.first)
        let resource = JsonResource(appId: "test40", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        // 验证带有 userId, roleId 和 logger 的 async 接口
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId,
            userId: user.id,
            roleId: role.id,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.read),
            privilegeIds: [privilege.id]
        )
        
        #expect(allow.result == true)
        
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId,
            userId: user.id,
            roleId: role.id,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.write),
            privilegeIds: [privilege.id]
        )
        
        #expect(deny.result == false)
        
        // 清理
        try await m.privilege.delete(policy: privilege)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 4
    // Target Role: 7         [ Available ]
    // --------------------------------------------------
    // Inherit Group:None (Direct Mode)
    // --------------------------------------------------
    // Active Role: Role-7    ➔  allow if { true }
    // Bound Domain:Domain-6  ➔  allow if { true }
    // Bound Domain:Domain-7  ➔  allow if { true }
    // ==================================================
    // allow
    @Test("边界：有直接用户域的无group用户，domain reports 不为空")
    func edge_NoGroupUser_HasDirectDomainReports() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user4: userInGroups[4]=[] (无 group)，但直接赋予 domain6/domain7
        // domain6/domain7 均为 allow if {true}，空 resource 也通过
        let user = try await fetchUser(index: 4, s: s)
        let role = try await fetchRole(index: 7, s: s) // RT[7]: user4 的用户角色

        let resource = JsonResource(appId: "test41", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(res.result, "RT[7](allow all) + domain6/7(allow all) → ALLOW")
        let domainReports = res.reports.filter { $0.key.type == .domain }
        #expect(!domainReports.isEmpty, "user4 有直接赋予的 domain6/domain7，应有 domain 报告")
        #expect(domainReports.count == 2, "domain6 和 domain7 共 2 个")
        #expect(domainReports.values.allSatisfy { $0 }, "domain6/domain7 均通过")
        try #require(res.reports.count == 3)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[2].key.type == .domain)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 9
    // Target Role: 7         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-11
    // --------------------------------------------------
    // Active Role: Role-7    ➔  allow if { true }
    // Bound Domain:None
    // ==================================================
    // allow
    @Test("边界：没有任何域约束的用户，仅产生 role report")
    func edge_NoDomainConstraints_RoleOnlyReport() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user9 在 group11 中；group11 没有 domain，user9 也没有直接 domain。
        // RT[7] 通过 roleForGroupUser 指派给 user9 in group11。
        let user = try await fetchUser(index: 9, s: s)
        let role = try await fetchRole(index: 7, s: s)

        let resource = JsonResource(appId: "test42", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.anything), privilegeIds: []
        )

        #expect(res.result, "无 domain/privilege 约束时，role 通过即可 ALLOW")
        #expect(res.reports.filter { $0.key.type == .role }.count == 1)
        #expect(res.reports.filter { $0.key.type == .domain }.isEmpty)
        #expect(res.reports.filter { $0.key.type == .privilege }.isEmpty)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 0         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-0    ➔  allow if { input.operation == "manage_all" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // deny -> false, true
    @Test("边界：role 失败时 AND 逻辑使最终结果为 false")
    func edge_RoleFailsAndShortCircuit() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user0 可用角色: RT[0](SuperAdmin), RT[3](Observer)
        // user0 在 group0，绑 domain0(global==true)
        // 测试：SuperAdmin+view → role 失败，即使 domain0 通过也 DENY
        let user = try await fetchUser(index: 0, s: s)
        let role = try await fetchRole(index: 0, s: s) // RT[0] = SuperAdminRole: manage_all only
        let rolePolicy = try #require(try await fetchRolePolicy(index: 0, s: s).first)

        let resource = JsonResource(appId: "test43", content: ["global": AnyCodable(true)]) // domain0 通过
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(!res.result, "role 失败（SuperAdmin 不含 view）→ DENY")
        let roleKey = PrivilegeSystem.Arbitrator.Result.IdKey(type: .role, moduleId: m.moduleId, modelId: role.id, policyId: rolePolicy.id)
        #expect(res.reports[roleKey] == false)
        try #require(res.reports.count == 2)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[0].value == false)
        #expect(res.reports.elements[1].value == true)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 4
    // Target Role: 0         [ Unavailable ]
    // --------------------------------------------------
    // Inherit Group:None (Direct Mode)
    // --------------------------------------------------
    // Active Role: None
    // Bound Domain:Domain-6  ➔  allow if { true }
    // Bound Domain:Domain-7  ➔  allow if { true }
    // ==================================================
    // Error! role not available
    @Test("边界：传入不属于用户的 role 时，judge 在策略查询前失败")
    func edge_UnavailableRoleRejectedBeforePolicyEvaluation() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 4, s: s)
        let role = try await fetchRole(index: 0, s: s) // RT[0] 不属于 user4

        do {
            let resource = JsonResource(appId: "test44", content: ["global": AnyCodable(true)])
            let resourceDTO = try await m.resource.create(resources: [resource]).first!
            
            _ = try await s.arbitrator.judge(
                moduleId: m.moduleId, user: user, role: role,
                resource: try #require(GResource(resourceDTO)),
                operation: .init(op: JsonOperation.manage_all), privilegeIds: []
            )
            Issue.record("不可用 role 不应进入仲裁策略查询")
        } catch let err {
            let e = try #require(err as? PrivilegeSystem.Errcase.ErrType)
            #expect(e.error == .arbitrationDataCollectFailed)
        }
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 6
    // Target Role: 10        [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-6
    // Inherit Group:Group-7
    // --------------------------------------------------
    // Active Role: Role-10   ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-4  ➔  allow if { true }
    // ==================================================
    // allow
    @Test("边界：默认域策略 allow if {true} 对所有 resource 放行")
    func edge_DefaultDomainAllowsAll() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user6 在 GT.ids[6,7](SalesTeam+MarketingTeam)
        // group6/7 直接绑 domain4(默认 allow if {true})
        // 但父群组 group0 绑 domain0(global==true) 也会继承到 user6
        // 所以 resource={} 时 domain0(global==true) 失败 → DENY
        // 改为测试 global=true 时，domain4 + domain0 全部通过
        // user6 可用角色: RT[10](用户角色), RT[4](组内角色 in group6)
        let user = try await fetchUser(index: 6, s: s)
        let role = try await fetchRole(index: 10, s: s) // RT[10]: allow if {true}

        let resource = JsonResource(appId: "test45", content: ["global": AnyCodable(true)]) // 满足继承s的 domain0
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(res.result, "RT[10](allow all) + domain4(allow all) + domain0(global=true) 全通过 → ALLOW")
        try #require(res.reports.count == 3)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[2].key.type == .domain)
    }

    // =========================================================================
    // MARK: 13. 嵌套群组域权限继承
    // =========================================================================
    // 验证：当用户处于子群组时，所有父群组绑定的域策略都会叠加到鉴权链路中。
    //
    // 嵌套结构（由 GroupTests + RelationTests 建立）：
    //   GT.ids[0] (AdministratorGroup) ← domain0: global==true
    //       ├─ GT.ids[6]  (SalesTeam)        ← domain4: allow if {true}
    //       └─ GT.ids[7]  (MarketingTeam)    ← domain4: allow if {true}
    //   GT.ids[1] (OperatorGroup) ← domain1: region=="asia"
    //       └─ GT.ids[8]  (HumanResources)
    //   GT.ids[2] (DeveloperHub) ← domain2: region=="na"
    //       ├─ GT.ids[9]  (QualityAssurance)
    //       └─ GT.ids[10] (Designers)
    //
    // AT.ids[6] → [group6, group7]  继承 domain0 (GlobalScope)
    // AT.ids[7] → [group8, group9]  继承 domain1 (AsiaPacific) + domain2 (NorthAmerica)
    // AT.ids[8] → [group10]         继承 domain2 (NorthAmerica)
    // =========================================================================

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 6
    // Target Role: 10        [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-6
    // Inherit Group:Group-7
    // --------------------------------------------------
    // Active Role: Role-10   ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-4  ➔  allow if { true }
    // ==================================================
    // allow
    @Test("嵌套群组：子群组用户继承父群组 domain0(global==true) → global=true ALLOW")
    func nestedGroup_InheritParentDomain_Allow() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user6 可用角色: RT[10](用户角色, allow if {true}), RT[4](组内角色 in group6, allow if {true})
        // group6/7 父群组 group0 绑 domain0(global==true) 会继承到 user6
        // group6/7 直接绑 domain4(allow if {true})
        let user = try await fetchUser(index: 6, s: s)
        let role = try await fetchRole(index: 10, s: s) // RT[10]: allow if {true}

        let resource = JsonResource(appId: "test46", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(allow.result, "子群组用户 + 满足父群组 domain0(global=true) → ALLOW")

        let domainReports = allow.reports.filter { $0.key.type == .domain }
        #expect(!domainReports.isEmpty, "嵌套群组用户应有 domain 报告")
        #expect(domainReports.values.allSatisfy { $0 }, "所有 domain 报告都应为 true")
        try #require(allow.reports.count == 3)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)
        #expect(allow.reports.elements[2].key.type == .domain)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 6
    // Target Role: 11        [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-6
    // Inherit Group:Group-7
    // --------------------------------------------------
    // Active Role: Role-11   ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-4  ➔  allow if { true }
    // ==================================================
    // allow
    @Test("嵌套群组：父群组角色对直接子群组用户可用，并参与仲裁")
    func nestedGroup_ParentGroupRoleAvailableToChildUser() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // Shared.roleForGroup[11] = [group0]，user6 在 group6/group7，二者均为 group0 子群组。
        let user = try await fetchUser(index: 6, s: s)
        let role = try await fetchRole(index: 11, s: s) // RT[11]: allow if {true}
        let rolePolicy = try #require(try await fetchRolePolicy(index: 11, s: s).first)

        let applicableGroups = try await s.role.verify(groupRole: role, appointedTo: user)
        #expect(applicableGroups.map { $0.id }.contains(GT.ids[0]), "RT[11] 应作为父群组 group0 的群组角色对 user6 可用")

        let resource = JsonResource(appId: "test47", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )

        #expect(res.result, "父群组角色 + 继承 domain0(global=true) + 子群组 domain4 → ALLOW")
        let roleKey = PrivilegeSystem.Arbitrator.Result.IdKey(type: .role, moduleId: m.moduleId, modelId: role.id, policyId: rolePolicy.id)
        #expect(res.reports[roleKey] == true)
        #expect(res.reports.filter { $0.key.type == .domain }.values.allSatisfy { $0 })
        try #require(res.reports.count == 3)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[2].key.type == .domain)
    }
    
    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 6
    // Target Role: 4         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-6
    // Inherit Group:Group-7
    // --------------------------------------------------
    // Active Role: Role-4    ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-4  ➔  allow if { true }
    // ==================================================
    // deny -> true, false, true
    @Test("嵌套群组：子群组用户父群组 domain0(global==true) 不满足 → global=false DENY")
    func nestedGroup_InheritParentDomain_Deny() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 6, s: s)
        // RT[4]: user6 的组内角色(in group6), allow if {true}
        let role = try await fetchRole(index: 4, s: s)

        let resource = JsonResource(appId: "test48", content: ["global": AnyCodable(false)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.any), privilegeIds: []
        )
        #expect(!deny.result, "global=false → 继承的 domain0 失败 → DENY")

        let domainReports = deny.reports.filter { $0.key.type == .domain }
        #expect(domainReports.values.contains(false), "domain0 报告应为 false")
        try #require(deny.reports.count == 3)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[2].key.type == .domain)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == false)
        #expect(deny.reports.elements[2].value == true)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 0         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-0    ➔  allow if { input.operation == "manage_all" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // deny -> false, true
    @Test("嵌套群组：role 失败时即使父群组域策略全通过也应 DENY")
    func nestedGroup_RoleFailsOverridesDomain() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user6 可用角色: RT[10](allow if {true}), RT[4](allow if {true})
        // 两种都是 allow all，无法测试 role 失败场景
        // 改为使用 user0(group0)：RT[0](SuperAdmin) + view 操作 → role 失败
        // user0 可用角色: RT[0](SuperAdmin), RT[3](Observer in-group)
        let user = try await fetchUser(index: 0, s: s) // user0 在 group0(domain0: global==true)
        let role = try await fetchRole(index: 0, s: s) // RT[0] SuperAdminRole: manage_all only
        let rolePolicy = try #require(try await fetchRolePolicy(index: 0, s: s).first)

        let resource = JsonResource(appId: "test49", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(!res.result, "SuperAdminRole 不允许 view → DENY，即使 domain 全通过")
        let roleKey = PrivilegeSystem.Arbitrator.Result.IdKey(
            type: .role, moduleId: m.moduleId, modelId: role.id, policyId: rolePolicy.id)
        #expect(res.reports[roleKey] == false)
        try #require(res.reports.count == 2)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)
        #expect(res.reports.elements[0].value == false)
        #expect(res.reports.elements[1].value == true)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 7
    // Target Role: 11        [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-1
    // Inherit Group:Group-2
    // Inherit Group:Group-8
    // Inherit Group:Group-9
    // --------------------------------------------------
    // Active Role: Role-11   ➔  allow if { true }
    // Bound Domain:Domain-1  ➔  allow if { input.resource.region == "asia" }
    // Bound Domain:Domain-2  ➔  allow if { input.resource.region == "na" }
    // ==================================================
    // 1: deny -> true, true, false
    // 2: deny -> true, false, true
    // 3: deny -> true, false, false
    @Test("嵌套群组：用户在两个不同父群组的子群组中 → 两个父群组域策略均须满足")
    func nestedGroup_MultiParentDomains_MustAllPass() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // AT.ids[7] → group8 (HumanResources，child of group1/OperatorGroup: domain1 region=asia)
        //           + group9 (QualityAssurance，child of group2/DeveloperHub: domain2 region=na)
        // domain1 要求 region="asia"，domain2 要求 region="na" → 两者互斥，始终 DENY
        // user7 可用角色: RT[11](用户角色, allow if {true}), RT[5](组内角色 in group8, allow if {true})
        let user = try await fetchUser(index: 7, s: s)
        let role = try await fetchRole(index: 11, s: s) // RT[11]: allow if {true}

        let resource = JsonResource(appId: "test50", content: ["region": AnyCodable("asia")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        // 尝试只满足 domain1
        let denyWithAsia = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(!denyWithAsia.result, "region=asia → domain1 通过但 domain2(na) 失败 → DENY")
        try #require(denyWithAsia.reports.count == 3)
        #expect(denyWithAsia.reports.elements[0].key.type == .role)
        #expect(denyWithAsia.reports.elements[1].key.type == .domain)
        #expect(denyWithAsia.reports.elements[2].key.type == .domain)
        #expect(denyWithAsia.reports.elements[0].value == true)
        #expect(denyWithAsia.reports.elements[1].value == true)
        #expect(denyWithAsia.reports.elements[2].value == false)

        let resource2 = JsonResource(appId: "test51", content: ["region": AnyCodable("na")])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        // 尝试只满足 domain2
        let denyWithNa = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(!denyWithNa.result, "region=na → domain2 通过但 domain1(asia) 失败 → DENY")
        try #require(denyWithNa.reports.count == 3)
        #expect(denyWithNa.reports.elements[0].key.type == .role)
        #expect(denyWithNa.reports.elements[1].key.type == .domain)
        #expect(denyWithNa.reports.elements[2].key.type == .domain)
        #expect(denyWithNa.reports.elements[0].value == true)
        #expect(denyWithNa.reports.elements[1].value == false)
        #expect(denyWithNa.reports.elements[2].value == true)

        let resource3 = JsonResource(appId: "test52", content: [:])
        let resourceDTO3 = try await m.resource.create(resources: [resource3]).first!
        
        // 两者均不满足
        let denyEmpty = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO3)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(!denyEmpty.result, "无 region → 两个父群组域策略均失败 → DENY")
        let domainReports = denyEmpty.reports.filter { $0.key.type == .domain }
        #expect(domainReports.values.allSatisfy { !$0 }, "所有继承域报告应为 false")
        try #require(denyEmpty.reports.count == 3)
        #expect(denyEmpty.reports.elements[0].key.type == .role)
        #expect(denyEmpty.reports.elements[1].key.type == .domain)
        #expect(denyEmpty.reports.elements[2].key.type == .domain)
        #expect(denyEmpty.reports.elements[0].value == true)
        #expect(denyEmpty.reports.elements[1].value == false)
        #expect(denyEmpty.reports.elements[2].value == false)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 8
    // Target Role: 12        [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-2
    // Inherit Group:Group-10
    // --------------------------------------------------
    // Active Role: Role-12   ➔  allow if { true }
    // Bound Domain:Domain-2  ➔  allow if { input.resource.region == "na" }
    // ==================================================
    // 1: allow
    // 2: deny -> true, false
    @Test("嵌套群组：单一子群组用户继承父群组 domain2(region=na)")
    func nestedGroup_SingleChildInheritsParentDomain2() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // AT.ids[8] → group10 (Designers，child of group2/DeveloperHub: domain2 region=na)
        // user8 可用角色: RT[12], RT[13](用户角色, allow if {true}), RT[6](组内角色 in group10, allow if {true})
        let user = try await fetchUser(index: 8, s: s)
        let role = try await fetchRole(index: 12, s: s) // RT[12]: allow if {true}

        let resource = JsonResource(appId: "test53", content: ["region": AnyCodable("na")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(allow.result, "region=na → 继承的 domain2 通过 → ALLOW")
        try #require(allow.reports.count == 2)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)

        let resource2 = JsonResource(appId: "test54", content: ["region": AnyCodable("asia")])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(!deny.result, "region=asia → 继承的 domain2(na) 失败 → DENY")
        try #require(deny.reports.count == 2)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == false)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 6
    // Target Role: 10        [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-6
    // Inherit Group:Group-7
    // --------------------------------------------------
    // Active Role: Role-10   ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-4  ➔  allow if { true }
    // ==================================================
    // 1: allow
    // 2: deny -> true, false, true
    @Test("嵌套群组：子群组直接域策略与父群组继承域策略 AND 叠加验证")
    func nestedGroup_DirectAndInheritedDomainsAND() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // AT.ids[6] → group6(SalesTeam) + group7(MarketingTeam)
        //   group6/7 直接绑定 domain4 (allow if {true}) → 始终通过
        //   group6/7 父群组 group0 绑定 domain0 (global==true) → 需 global=true
        // 总和: domain0(继承) AND domain4(直接) AND domain4(直接)
        // user6 可用角色: RT[10](用户角色, allow if {true}), RT[4](组内角色 in group6, allow if {true})
        let user = try await fetchUser(index: 6, s: s)
        let role = try await fetchRole(index: 10, s: s) // RT[10]: allow if {true}

        let resource = JsonResource(appId: "test55", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        // global=true → 全通过
        let allPass = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(allPass.result, "domain4(直接) + domain0(继承, global=true) + RT[10](allow all) → ALLOW")
        let passDomainReports = allPass.reports.filter { $0.key.type == .domain }
        #expect(passDomainReports.count == 2, "group6/group7 重复获得 domain0/domain4 时，应按 domain id 去重为 2 个报告")
        #expect(passDomainReports.values.allSatisfy { $0 }, "domain0/domain4 均应通过")

        try #require(allPass.reports.count == 3)
        #expect(allPass.reports.elements[0].key.type == .role)
        #expect(allPass.reports.elements[1].key.type == .domain)
        #expect(allPass.reports.elements[2].key.type == .domain)
        
        let resource2 = JsonResource(appId: "test56", content: ["global": AnyCodable(false)])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        // global=false → domain0(继承) 失败 → DENY
        let inheritFail = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(!inheritFail.result, "domain0(继承) 失败 → 整体 DENY")
        
        try #require(inheritFail.reports.count == 3)
        #expect(inheritFail.reports.elements[0].key.type == .role)
        #expect(inheritFail.reports.elements[1].key.type == .domain)
        #expect(inheritFail.reports.elements[2].key.type == .domain)
        #expect(inheritFail.reports.elements[0].value == true)
        #expect(inheritFail.reports.elements[1].value == false)
        #expect(inheritFail.reports.elements[2].value == true)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 3         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-3    ➔  allow if { input.operation == "view" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // 1: allow
    // 2: deny -> true, false
    @Test("嵌套群组：用户直接域权限与所在子群组继承的父群组域权限并行验证")
    func nestedGroup_UserDirectDomainPlusInherited() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // AT.ids[0] 在 group0 (AdministratorGroup) 中
        // AT.ids[0] 同时被直接赋予 domain0 (GlobalScope: global==true)
        // user0 可用角色: RT[0](SuperAdmin), RT[3](Observer in-group)—使用 RT[3](Observer)
        let user = try await fetchUser(index: 0, s: s)
        let role = try await fetchRole(index: 3, s: s) // RT[3] ObserverRole: view

        let resource = JsonResource(appId: "test57", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(res.result, "用户直接域 + 群组域均满足 global=true → ALLOW")

        let domainReports = res.reports.filter { $0.key.type == .domain }
        #expect(!domainReports.isEmpty, "应有 domain 报告")
        #expect(domainReports.count == 1, "domain0 同时来自用户直接域和群组域，reports 应按 domain id 去重")
        #expect(domainReports.values.allSatisfy { $0 }, "所有 domain 报告均为 true")
        
        try #require(res.reports.count == 2)
        #expect(res.reports.elements[0].key.type == .role)
        #expect(res.reports.elements[1].key.type == .domain)

        let resource2 = JsonResource(appId: "test58", content: ["global": AnyCodable(false)])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        // global=false → domain0 均失败 → DENY
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(!deny.result, "global=false → 用户直接域 + 群组域 domain0 均失败 → DENY")
        
        try #require(deny.reports.count == 2)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == false)
    }


    // =========================================================================
    // MARK: 14. 组内角色（appoint / dismiss 动态场景）
    // =========================================================================
    // 设计图（diagrams/9.组内角色.png）要点：
    //   组内角色只在该群组内对指定用户生效。
    //   用户脱离该群组后，角色自动失效（鉴权时不再使用该角色）。
    //   同一用户可在不同群组中担任不同组内角色。
    //
    // 已有固定场景（RelationTests 建立）：
    //   RT.ids[3] (ObserverRole) → AT.ids[0] in GT.ids[0]
    //   RT.ids[4] (SalesManager) → AT.ids[6] in GT.ids[6]
    //   RT.ids[5] (HRLead)       → AT.ids[7] in GT.ids[8]
    //
    // 本节额外动态 appoint/dismiss：使用 RT.ids[2] 对 AT.ids[8] 进行组内角色指派和撤销。
    // =========================================================================

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 3         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-3    ➔  allow if { input.operation == "view" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // ==================================================
    // 1: allow
    // 2: deny -> true, false
    @Test("组内角色：RelationTests 中已指派 ObserverRole 到 user0 in group0，judge 通过")
    func inGroupRole_ExistingAssignment_ObserverInGroup0() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // RT.ids[3] (ObserverRole: view) → AT.ids[0] in GT.ids[0]
        // AT.ids[0] 在 group0 中，group0 绑 domain0 (global==true)
        let user = try await fetchUser(index: 0, s: s)
        let role = try await fetchRole(index: 3, s: s)

        let resource = JsonResource(appId: "test59", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        // domain 满足 + role 满足 → ALLOW
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(allow.result, "ObserverRole(view) + domain0(global=true) → ALLOW")
        
        try #require(allow.reports.count == 2)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)
        
        let resource2 = JsonResource(appId: "test60", content: ["global": AnyCodable(false)])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        // domain 失败 → DENY（组内角色不能越过域策略）
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(!deny.result, "global=false → domain0 失败 → DENY 即使有组内角色")
        
        try #require(deny.reports.count == 2)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == false)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 6
    // Target Role: 4         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // Inherit Group:Group-6
    // Inherit Group:Group-7
    // --------------------------------------------------
    // Active Role: Role-4    ➔  allow if { true }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Bound Domain:Domain-4  ➔  allow if { true }
    // ==================================================
    // 1: allow
    // 2: deny -> true, false, true
    @Test("组内角色：RelationTests 中已指派 SalesManager(RT.ids[4]) 到 user6 in group6，嵌套域策略和组内角色共同生效")
    func inGroupRole_ExistingAssignment_SalesManagerInGroup6() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // RT.ids[4] (SalesManager: allow if {true}) → AT.ids[6] in GT.ids[6]
        // AT.ids[6] 在 group6(SalesTeam) + group7(MarketingTeam) 中
        // group6/7 直接绑 domain4 (allow if {true})，且父群组 group0 绑 domain0 (global==true)
        let user = try await fetchUser(index: 6, s: s)
        let role = try await fetchRole(index: 4, s: s) // SalesManager: allow if {true}

        let resource = JsonResource(appId: "test61", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        // SalesManager 策略 allow if {true}，global=true 满足 domain0 → ALLOW
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.any_operation), privilegeIds: []
        )
        #expect(allow.result, "SalesManager(allow all) + domain0(global=true) + domain4(allow all) → ALLOW")

        try #require(allow.reports.count == 3)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)
        #expect(allow.reports.elements[2].key.type == .domain)
        
        let resource2 = JsonResource(appId: "test62", content: ["global": AnyCodable(false)])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        // global=false → 父群组 domain0 失败 → DENY
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.any_operation), privilegeIds: []
        )
        #expect(!deny.result, "global=false → 继承的 domain0 失败 → DENY 即使是组内角色")
        
        try #require(deny.reports.count == 3)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[2].key.type == .domain)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == false)
        #expect(deny.reports.elements[2].value == true)
    }

    @Test("组内角色：动态 appoint，鉴权立即生效；dismiss 后验证撤销成功")
    func inGroupRole_DynamicAppointAndDismiss() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // 使用 RT.ids[2] (ModeratorRole: moderate) 动态指派给 AT.ids[8] in GT.ids[10]
        // AT.ids[8] → group10 (Designers，child of group2/DeveloperHub: domain2 region=na)
        let user = try await fetchUser(index: 8, s: s)
        let role = try await fetchRole(index: 2, s: s) // ModeratorRole: moderate

        // ─── 第一步：查询 user8 在 group10 中的关系对 ────────────────────────
        let allGroups = try await s.origin.query(QGroup.self).all()
        let group10 = try #require(allGroups.first(where: { $0.id == GT.ids[10] }))

        let relReq = try await s.group.query(
            relations: [.init(userId: user.id, groupId: group10.id)]
        )
        let rel = try #require(
            relReq.first(where: { $0.userId == user.id && $0.groupId == group10.id }),
            "AT.ids[8] 应在 GT.ids[10] 中"
        )

        // ─── 第二步：appoint ModeratorRole → AT.ids[8] in GT.ids[10] ───────
        try await s.role.appoint {
            OrderedSet([role]) => OrderedSet([rel])
        }

        let resource = JsonResource(appId: "test63", content: ["region": AnyCodable("na")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        // ─── 第三步：鉴权验证（appoint 后应通过）────────────────────────────
        // ModeratorRole: moderate，group10 继承 domain2 (region=na)
        let allowAfterAppoint = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.moderate), privilegeIds: []
        )
        #expect(allowAfterAppoint.result, "appoint 后：ModeratorRole + domain2(region=na) → ALLOW")

        let resource2 = JsonResource(appId: "test64", content: ["region": AnyCodable("asia")])
        let resourceDTO2 = try await m.resource.create(resources: [resource2]).first!
        
        // region=asia → domain2 失败 → DENY
        let denyDomain = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.moderate), privilegeIds: []
        )
        #expect(!denyDomain.result, "region=asia → domain2(na) 失败 → DENY")

        // ─── 第四步：dismiss，撤销 ModeratorRole ────────────────────────────
        try await s.role.dismiss {
            OrderedSet([role]) => OrderedSet([rel])
        }

        // dismiss 后 ModeratorRole 不再是 user8 的可用身份；不要再用它调用 judge。
        let stillAvailable = try await s.role.is(role: role, appointedTo: user)
        #expect(!stillAvailable, "dismiss 后 ModeratorRole 不应再属于 user8")
    }

    @Test("组内角色：同一用户在不同群组担任不同组内角色，两角色互相独立")
    func inGroupRole_SameUserDifferentGroupRoles() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // AT.ids[7] 在 group8(HumanResources) 和 group9(QualityAssurance) 中
        // RelationTests 中 RT.ids[5](HRLead, allow if {true}) → AT.ids[7] in GT.ids[8]
        // 动态再指派 RT.ids[6](allow if {true}) → AT.ids[7] in GT.ids[9]
        let user = try await fetchUser(index: 7, s: s)
        let hrLeadRole = try await fetchRole(index: 5, s: s) // HRLead: allow if {true}
        let role6 = try await fetchRole(index: 6, s: s)      // RT.ids[6]: allow if {true}

        let allGroups = try await s.origin.query(QGroup.self).all()
        let group9 = try #require(allGroups.first(where: { $0.id == GT.ids[9] }))

        let relReq = try await s.group.query(
            relations: [.init(userId: user.id, groupId: group9.id)]
        )
        let relInGroup9 = try #require(
            relReq.first(where: { $0.userId == user.id && $0.groupId == group9.id }),
            "AT.ids[7] 应在 GT.ids[9] 中"
        )

        // 动态指派 role6 → user7 in group9
        try await s.role.appoint {
            OrderedSet([role6]) => OrderedSet([relInGroup9])
        }

        let resource = JsonResource(appId: "test65", content: ["region": AnyCodable("asia")])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        // ─── 测试场景：HRLead + group8 继承 domain1(asia) → 只满足 asia ───
        // HRLead(allow all) + group8 的父群组域策略(domain1: region=asia)
        // 注意：user7 在 group8 AND group9，两个父群组域策略均生效
        // group8 父群组: domain1 (region=asia)
        // group9 父群组: domain2 (region=na)
        // 两者互斥 → 始终 DENY
        let alwaysDeny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: hrLeadRole,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.hr_task), privilegeIds: []
        )
        #expect(!alwaysDeny.result,
                "user7 在 group8+group9，父群组 domain1(asia) AND domain2(na) 互斥 → 始终 DENY")

        // 清理：dismiss role6 from user7 in group9
        try await s.role.dismiss {
            OrderedSet([role6]) => OrderedSet([relInGroup9])
        }
    }

    @Test("组内角色：judge 传入的 role 决定策略，组内指派不影响其他 role 的 judge 结果")
    func inGroupRole_ScopeIsolation_NotGlobal() async throws {
        let (s, m) = try await TestingShared.getSystem()
        // user0 在 group0 中，RelationTests 将 ObserverRole(view) 指派到 user0 in group0
        // user0 可用角色: RT[0](SuperAdmin, 用户角色), RT[3](Observer, 组内角色)
        // 测试: 当使用 RT[0](SuperAdmin) + view 操作 → role 策略不允许 → DENY
        // 组内 RT[3](Observer) 的存在不干扰 RT[0] 的判定
        let user = try await fetchUser(index: 0, s: s)
        let superAdminRole = try await fetchRole(index: 0, s: s) // RT[0]: manage_all only

        let resource = JsonResource(appId: "test66", content: ["global": AnyCodable(true)])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        // RT[0] + view → role 策略不通过 → DENY（组内 RT[3] 不干扰）
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: superAdminRole,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(!deny.result, "RT[0] 不允许 view → DENY，组内 RT[3] 不影响此次 judge")

        // RT[0] + manage_all + domain0(global=true) → ALLOW
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: superAdminRole,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.manage_all), privilegeIds: []
        )
        #expect(allow.result, "RT[0] + manage_all + domain0(global=true) → ALLOW")

        // 切换为 RT[3](Observer) + view + global=true → ALLOW
        let observerRole = try await fetchRole(index: 3, s: s)
        let allowObserver = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: observerRole,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.view), privilegeIds: []
        )
        #expect(allowObserver.result, "RT[3](Observer) + view + global=true → ALLOW")
    }

    // =========================================================================
    // MARK: Resource 与 Privilege 的结合测试
    // =========================================================================

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 1
    // Target Role: 1         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-1
    // --------------------------------------------------
    // Active Role: Role-1    ➔  allow if { input.operation == "edit" } allow if { input.operation == "publish" }
    // Bound Domain:Domain-1  ➔  allow if { input.resource.region == "asia" }
    // Resource               ➔  allow if { input.resource.isPrivate == false; input.operation == "edit" }
    // ==================================================
    // 1: allow
    // 2: deny -> true, true, false
    @Test("Resource + Privilege：Privilege 的策略依赖 resource 的属性，当条件满足时 ALLOW")
    func edge_PrivilegeAndResource_Allowed() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 1, s: s)
        let role = try await fetchRole(index: 1, s: s) // EditorRole: edit 或 publish
        
        let jsonResource = JsonResource(appId: "public_doc_1.txt", content: ["isPrivate": AnyCodable(false), "region": AnyCodable("asia")])
        let resourceDTO = try await m.resource.create(resources: [jsonResource]).first!
        let anyResourceDTO = try #require(GResource(resourceDTO))
        
        // Privilege 策略：要求 input.resource.isPrivate == false 且 operation == edit
        let privileges = try await m.privilege.createWithReturning(privileges: [
            .init(
                name: "PublicFileEdit",
                policy: "allow if { input.resource.isPrivate == false; input.operation == \"edit\" }"
            )
        ])
        let privilegeDTO = privileges[0]
        
        try await m.privilege.attach {
            OrderedSet([privilegeDTO]) => OrderedSet([anyResourceDTO])
        }
        
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: anyResourceDTO,
            operation: .init(op: JsonOperation.edit), privilegeIds: [privilegeDTO.id]
        )
        
        #expect(allow.result, "Resource.isPrivate == false 且 operation == edit，且满足 role/domain，-> ALLOW")
        
        try #require(allow.reports.count == 3)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)
        #expect(allow.reports.elements[2].key.type == .privilege)
        
        // 验证其他操作被拒绝 (role 允许 publish，但 privilege 拒绝)
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: anyResourceDTO,
            operation: .init(op: JsonOperation.publish), privilegeIds: [privilegeDTO.id]
        )
        
        #expect(!deny.result, "operation == publish，Privilege 拒绝 -> DENY")
        
        // 清理
        try await m.privilege.detach {
            OrderedSet([privilegeDTO]) => OrderedSet([anyResourceDTO])
        }
        try await m.privilege.delete(policy: privilegeDTO)
        try await m.resource.delete(ids: [resourceDTO.id])
        
        try #require(deny.reports.count == 3)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[2].key.type == .privilege)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == true)
        #expect(deny.reports.elements[2].value == false)
    }

    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 1
    // Target Role: 1         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-1
    // --------------------------------------------------
    // Active Role: Role-1    ➔  allow if { input.operation == "edit" } allow if { input.operation == "publish" }
    // Bound Domain:Domain-1  ➔  allow if { input.resource.region == "asia" }
    // Resource               ➔  allow if { input.resource.isPrivate == false; input.operation == "edit" }
    // ==================================================
    // deny -> true, true, false
    @Test("Resource + Privilege：Privilege 的策略依赖 resource 的属性，当条件不满足时 DENY")
    func edge_PrivilegeAndResource_Denied() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 1, s: s)
        let role = try await fetchRole(index: 1, s: s) // EditorRole: edit or publish
        
        // 这是一个私有文件
        let jsonResource = JsonResource(appId: "secret_keys_1.env", content: ["isPrivate": AnyCodable(true), "region": AnyCodable("asia")])
        let resourceDTO = try await m.resource.create(resources: [jsonResource]).first!
        let anyResourceDTO = try #require(GResource(resourceDTO))
        
        // Privilege 策略：要求 input.resource.isPrivate == false
        let privileges = try await m.privilege.createWithReturning(privileges: [
            .init(
                name: "PublicFileEdit_DenyTest",
                policy: "allow if { input.resource.isPrivate == false; input.operation == \"edit\" }"
            )
        ])
        let privilegeDTO = privileges[0]
        
        try await m.privilege.attach {
            OrderedSet([privilegeDTO]) => OrderedSet([anyResourceDTO])
        }
        
        // 尝试 edit (符合 role 策略，但被 privilege 策略拒绝)
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: anyResourceDTO,
            operation: .init(op: JsonOperation.edit), privilegeIds: [privilegeDTO.id]
        )
        
        #expect(!deny.result, "Resource.isPrivate == true，不满足 Privilege 策略(isPrivate == false) → DENY")
        
        // 清理
        try await m.privilege.detach {
            OrderedSet([privilegeDTO]) => OrderedSet([anyResourceDTO])
        }
        try await m.privilege.delete(policy: privilegeDTO)
        try await m.resource.delete(ids: [resourceDTO.id])
        
        try #require(deny.reports.count == 3)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[2].key.type == .privilege)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == true)
        #expect(deny.reports.elements[2].value == false)
    }
    
    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 1
    // Target Role: 1         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-1
    // --------------------------------------------------
    // Active Role: Role-1    ➔  allow if { input.operation == "edit" } allow if { input.operation == "publish" }
    // Bound Domain:Domain-1  ➔  allow if { input.resource.region == "asia" }
    // Resource               ➔  allow if { input.resource.ownerId == input.user.id }
    // ==================================================
    // 1: allow
    // ==================================================
    //  RBAC Privilege Relations Analysis Report
    // ==================================================
    // Target User: 0
    // Target Role: 0         [ Available ]
    // --------------------------------------------------
    // Inherit Group:Group-0
    // --------------------------------------------------
    // Active Role: Role-0    ➔  allow if { input.operation == "manage_all" }
    // Bound Domain:Domain-0  ➔  allow if { input.resource.global == true }
    // Resource               ➔  allow if { input.resource.ownerId == input.user.id }
    // ==================================================
    // 2: deny -> true, true, false
    @Test("Resource + Privilege：针对 Directory 的属主判断")
    func edge_DirectoryResource_Owner() async throws {
        let (s, m) = try await TestingShared.getSystem()
        let user = try await fetchUser(index: 1, s: s)
        let role = try await fetchRole(index: 1, s: s) // EditorRole
        
        let jsonResource = JsonResource(appId: "user_home_1", content: ["ownerId": AnyCodable(user.id.uuidString), "region": AnyCodable("asia")])
        let resourceDTO = try await m.resource.create(resources: [jsonResource]).first!
        let anyResourceDTO = try #require(GResource(resourceDTO))
        
        // Privilege 策略：仅要求操作者是属主 (无特定 operation 要求，只要通过 role)
        let privileges = try await m.privilege.createWithReturning(privileges: [
            .init(
                name: "DirectoryOwnerOnly",
                policy: "allow if { input.resource.ownerId == input.user.id }"
            )
        ])
        let privilegeDTO = privileges[0]
        
        try await m.privilege.attach {
            OrderedSet([privilegeDTO]) => OrderedSet([anyResourceDTO])
        }
        
        let allow = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: anyResourceDTO,
            operation: .init(op: JsonOperation.edit), privilegeIds: [privilegeDTO.id]
        )
        
        #expect(allow.result, "Directory.ownerId 等于 user.id → ALLOW")
        
        try #require(allow.reports.count == 3)
        #expect(allow.reports.elements[0].key.type == .role)
        #expect(allow.reports.elements[1].key.type == .domain)
        #expect(allow.reports.elements[2].key.type == .privilege)
        
        // 测试非属主被拒绝
        // 使用 user0(SuperAdmin), 其带有 global 的要求
        let otherUser = try await fetchUser(index: 0, s: s)
        let otherRole = try await fetchRole(index: 0, s: s)
        
        let jsonResourceOther = JsonResource(appId: "user_home_2", content: ["ownerId": AnyCodable(user.id.uuidString), "global": AnyCodable(true)])
        let resourceDTO2 = try await m.resource.create(resources: [jsonResourceOther]).first!
        let deny = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: otherUser, role: otherRole,
            resource: try #require(GResource(resourceDTO2)),
            operation: .init(op: JsonOperation.manage_all), privilegeIds: [privilegeDTO.id]
        )
        
        #expect(!deny.result, "Directory.ownerId 不等于 otherUser.id (即 user0.id) → DENY")
        
        // 清理
        try await m.privilege.detach {
            OrderedSet([privilegeDTO]) => OrderedSet([anyResourceDTO])
        }
        try await m.privilege.delete(policy: privilegeDTO)
        try await m.resource.delete(ids: [resourceDTO.id])
        
        try #require(deny.reports.count == 3)
        #expect(deny.reports.elements[0].key.type == .role)
        #expect(deny.reports.elements[1].key.type == .domain)
        #expect(deny.reports.elements[2].key.type == .privilege)
        #expect(deny.reports.elements[0].value == true)
        #expect(deny.reports.elements[1].value == true)
        #expect(deny.reports.elements[2].value == false)
    }
    
    @Test("多策略角色权限仲裁测试")
    func multiPolicyRoleTest() async throws {
        let (s, m) = try await TestingShared.getSystem()
        
        let user = try await s.account.register(for: PUser(email: "multi_role_policy_testing@email.com", hashedPassword: Crypto.hash("1234567890").get()))
        let role = try await #require(s.role.create(roles: [.init(name: "Multi Policy Role", summary: "多权限角色")]).first)
        
        let rolePolicy1 = PPolicy<Role>(moduleId: m.moduleId, policy: "allow if { input.user.email == \"multi_role_policy_testing@email.com\" }")
        let rolePolicy2 = PPolicy<Role>(moduleId: m.moduleId, policy: "allow if { input.role.name == \"Never!\" }")
        let rolePolicy3 = PPolicy<Role>(moduleId: m.moduleId, policy: "allow if { input.role.name == \"Multi Policy Role\" }")
        
        try await s.role.appoint {
            OrderedSet([role]) => OrderedSet([user])
        }
        
        let policyRelations = try await s.policy.createWithReturning(to: Role.self) {
            OrderedSet([rolePolicy1, rolePolicy2, rolePolicy3]) => role.id
        }

        let resource = JsonResource(appId: "test202", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.anything), privilegeIds: []
        )
        
        #expect(res.result == false)
        #expect(res.reports.count == 3)
        let key1 = PrivilegeSystem.Arbitrator.Result.IdKey(type: .role, moduleId: m.moduleId, modelId: role.id, policyId: policyRelations[role.id]![0].id)
        #expect(res.reports[key1] == true)
        let key2 = PrivilegeSystem.Arbitrator.Result.IdKey(type: .role, moduleId: m.moduleId, modelId: role.id, policyId: policyRelations[role.id]![1].id)
        #expect(res.reports[key2] == false)
        let key3 = PrivilegeSystem.Arbitrator.Result.IdKey(type: .role, moduleId: m.moduleId, modelId: role.id, policyId: policyRelations[role.id]![2].id)
        #expect(res.reports[key3] == true)
    }
    
    @Test("多策略角色权限仲裁测试-通过")
    func multiPolicyRoleTest_pass() async throws {
        let (s, m) = try await TestingShared.getSystem()
        
        let user = try await s.account.register(for: PUser(email: "multi_role_policy_testing_should_pass@email.com", hashedPassword: Crypto.hash("1234567890").get()))
        let role = try await #require(s.role.create(roles: [.init(name: "Multi Policy Should Pass Role", summary: "多权限角色")]).first)
        
        let rolePolicy1 = PPolicy<Role>(moduleId: m.moduleId, policy: "allow if { input.user.email == \"multi_role_policy_testing_should_pass@email.com\" }")
        let rolePolicy2 = PPolicy<Role>(moduleId: m.moduleId, policy: "allow if { input.role.name == \"Multi Policy Should Pass Role\" }")
        
        try await s.role.appoint {
            OrderedSet([role]) => OrderedSet([user])
        }
        
        let policyRelations = try await s.policy.createWithReturning(to: Role.self) {
            OrderedSet([rolePolicy1, rolePolicy2]) => role.id
        }

        let resource = JsonResource(appId: "test204", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.anything), privilegeIds: []
        )
        
        #expect(res.result == true)
        #expect(res.reports.count == 2)
        let key1 = PrivilegeSystem.Arbitrator.Result.IdKey(type: .role, moduleId: m.moduleId, modelId: role.id, policyId: policyRelations[role.id]![0].id)
        #expect(res.reports[key1] == true)
        let key2 = PrivilegeSystem.Arbitrator.Result.IdKey(type: .role, moduleId: m.moduleId, modelId: role.id, policyId: policyRelations[role.id]![1].id)
        #expect(res.reports[key2] == true)
    }
    
    @Test("多策略域权限仲裁测试")
    func multiPolicyDomainTest() async throws {
        let (s, m) = try await TestingShared.getSystem()
        
        let user = try await s.account.register(for: PUser(email: "multi_policy_domain_testing@email.com", hashedPassword: Crypto.hash("1234567890").get()))
        let domain = try await #require(s.domain.create(domains: [.init(name: "Multi Policy Domain", summary: "多权限角色")]).first)
        let role = try await #require(s.role.create(roles: [.init(name: "Empty Testing Role", summary: "无权限测试角色")]).first)
        
        let domainPolicy1 = PPolicy<Domain>(moduleId: m.moduleId, policy: "allow if { input.user.email == \"multi_policy_domain_testing@email.com\" }")
        let domainPolicy2 = PPolicy<Domain>(moduleId: m.moduleId, policy: "allow if { input.role.name == \"Never!\" }")
        let domainPolicy3 = PPolicy<Domain>(moduleId: m.moduleId, policy: "allow if { input.role.name == \"Multi Policy Role\" }")
        
        try await s.role.appoint {
            OrderedSet([role]) => OrderedSet([user])
        }
        
        try await s.domain.assign {
            OrderedSet([domain]) => OrderedSet([user])
        }
        
        let policyRelations = try await s.policy.createWithReturning(to: Domain.self) {
            OrderedSet([domainPolicy1, domainPolicy2, domainPolicy3]) => domain.id
        }

        let resource = JsonResource(appId: "test203", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.anything), privilegeIds: []
        )
        
        #expect(res.result == false)
        #expect(res.reports.count == 3)
        let key1 = PrivilegeSystem.Arbitrator.Result.IdKey(type: .domain, moduleId: m.moduleId, modelId: domain.id, policyId: policyRelations[domain.id]![0].id)
        #expect(res.reports[key1] == true)
        let key2 = PrivilegeSystem.Arbitrator.Result.IdKey(type: .domain, moduleId: m.moduleId, modelId: domain.id, policyId: policyRelations[domain.id]![1].id)
        #expect(res.reports[key2] == false)
        let key3 = PrivilegeSystem.Arbitrator.Result.IdKey(type: .domain, moduleId: m.moduleId, modelId: domain.id, policyId: policyRelations[domain.id]![2].id)
        #expect(res.reports[key3] == false)
    }
    
    @Test("多策略域权限仲裁测试-通过")
    func multiPolicyDomainTest_pass() async throws {
        let (s, m) = try await TestingShared.getSystem()
        
        let user = try await s.account.register(for: PUser(email: "multi_policy_domain_testing_should_pass@email.com", hashedPassword: Crypto.hash("1234567890").get()))
        let domain = try await #require(s.domain.create(domains: [.init(name: "Multi Policy Domain Should Pass", summary: "多权限角色")]).first)
        let role = try await #require(s.role.create(roles: [.init(name: "Empty Testing Role Should Pass", summary: "无权限测试角色")]).first)
        
        let domainPolicy1 = PPolicy<Domain>(moduleId: m.moduleId, policy: "allow if { input.user.email == \"multi_policy_domain_testing_should_pass@email.com\" }")
        let domainPolicy2 = PPolicy<Domain>(moduleId: m.moduleId, policy: "allow if { input.role.name == \"Empty Testing Role Should Pass\" }")
        
        try await s.role.appoint {
            OrderedSet([role]) => OrderedSet([user])
        }
        
        try await s.domain.assign {
            OrderedSet([domain]) => OrderedSet([user])
        }
        
        let policyRelations = try await s.policy.createWithReturning(to: Domain.self) {
            OrderedSet([domainPolicy1, domainPolicy2]) => domain.id
        }

        let resource = JsonResource(appId: "test205", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.anything), privilegeIds: []
        )
        
        #expect(res.result == true)
        #expect(res.reports.count == 2)
        let key1 = PrivilegeSystem.Arbitrator.Result.IdKey(type: .domain, moduleId: m.moduleId, modelId: domain.id, policyId: policyRelations[domain.id]![0].id)
        #expect(res.reports[key1] == true)
        let key2 = PrivilegeSystem.Arbitrator.Result.IdKey(type: .domain, moduleId: m.moduleId, modelId: domain.id, policyId: policyRelations[domain.id]![1].id)
        #expect(res.reports[key2] == true)
    }
    
    @Test("空权限仲裁测试")
    func emptyPrivilegeTest() async throws {
        let (s, m) = try await TestingShared.getSystem()
        
        let user = try await s.account.register(for: PUser(email: "empty_testing@email.com", hashedPassword: Crypto.hash("1234567890").get()))
        let role = try await #require(s.role.create(roles: [.init(name: "Empty Role", summary: "空权限角色")]).first)
        
        try await s.role.appoint {
            OrderedSet([role]) => OrderedSet([user])
        }

        let resource = JsonResource(appId: "test201", content: [:])
        let resourceDTO = try await m.resource.create(resources: [resource]).first!
        
        let res = try await s.arbitrator.judge(
            moduleId: m.moduleId, user: user, role: role,
            resource: try #require(GResource(resourceDTO)),
            operation: .init(op: JsonOperation.anything), privilegeIds: []
        )
        
        #expect(res.result == false)
        #expect(res.reports.count == 0)
    }

    // =========================================================================
    // MARK: 测试结束
    // =========================================================================

    @MainActor
    @Test("测试结束")
    func end() async throws {
        TestingShared.testStage = .init(rawValue: TestingShared.testStage.rawValue + 1)!
    }
}
