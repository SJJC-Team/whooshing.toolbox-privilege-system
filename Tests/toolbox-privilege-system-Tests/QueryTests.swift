import Testing
import Query
import Foundation
@testable import PrivilegeSystem

@Suite("Query 模块测试集", .serialized, .enabled(if: TestingShared.dbListening && TestingShared.opaListening))
struct QueryTests {
    
    @Test("开始测试")
    func start() async throws {
        while await TestingShared.testStage != .query {
            try await Task.sleep(nanoseconds: 250_000_000)
        }
    }
    
    @Test("基本过滤 (Filter)")
    func testFilter() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        let email = "user1@example.com" // 使用 AccountTests 中创建的邮箱
        
        let user = try await s.origin.query(QUser.self)
            .filter(\.email == email)
            .first()
            
            
        #expect(user != nil)
        #expect(user?.email == email)
    }
    
    @Test("连接查询 (Join)")
    func testJoin() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        // Join User 和 UserInfo
        let results = try await s.origin.query(QUser.self)
            .join(QUserInfo.self, on: \QUser.id == \QUserInfo.$user.id)
            .first()
            
            
        // 如果有匹配的数据，results 不为 nil
        // 这里只是验证 API 是否能正常执行不报错
        print("Join result: \(String(describing: results))")
    }
    
    @Test("分组查询 (Group)")
    func testGroup() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        // 测试 OR 条件
        let results = try await s.origin.query(QUser.self)
            .group(.or) { group in
                group.filter(\.email == "user1@example.com")
                group.filter(\.email == "user2@gmail.com")
            }
            .page(with: 1, size: 10)
            
            
        print("Group result count: \(results.items.count)")
    }
    
    @Test("分页查询 (Pagination)")
    func testPagination() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        let page = try await s.origin.query(QUser.self)
            .page(with: 1, size: 2)
            
            
        #expect(page.items.count <= 2)
        #expect(page.metadata.page == 1)
        #expect(page.metadata.per == 2)
    }
    
    @Test("分块查询 (Chunk)")
    func testChunk() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        class SafeCounter: @unchecked Sendable {
            private let lock = NSLock()
            var value = 0
            func add(_ n: Int) {
                lock.lock()
                defer { lock.unlock() }
                value += n
            }
        }
        let counter = SafeCounter()
        
        try await s.origin.query(QUser.self)
            .chunk(max: 2) { res in
                counter.add(res.count)
                print("Chunked \(res.count) items")
            }.get()
            
            
        print("Total items chunked: \(counter.value)")
    }
    
    @Test("其他 DTO 查询")
    func testOtherDTOs() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        // 查询 Domain
        let domain = try await s.origin.query(QDomain.self)
            .filter(\.name == "GlobalScope")
            .first()
            
            
        print("Domain result: \(String(describing: domain))")
        
        // 查询 Group
        let group = try await s.origin.query(QGroup.self)
            .filter(\.name == "AdministratorGroup")
            .first()
            
            
        print("Group result: \(String(describing: group))")
    }
    
    @Test("排序查询 (Sort)")
    func testSort() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        let users = try await s.origin.query(QUser.self)
            .sort(\.email, .descending)
            .page(with: 1, size: 10)
            
            
        print("Sorted users: \(users.items.map { $0.email })")
    }
    
    @Test("聚合查询 (Aggregate)")
    func testAggregate() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        let count = try await s.origin.query(QUser.self).count()
        print("Total users count: \(count)")
        
        #expect(count >= 0)
    }
    
    @Test("空结果分页查询 (Empty Pagination)")
    func testEmptyPagination() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        let page = try await s.origin.query(QUser.self)
            .filter(\.email == "nonexistent_email_12345@domain.com")
            .page(with: 1, size: 10)
            
        #expect(page.items.isEmpty)
        #expect(page.metadata.total == 0)
    }
    
    @Test("可选字段排序 (Sort Optional)")
    func testSortOptional() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        // QGroup.summary 是可选的 String?
        let groups = try await s.origin.query(QGroup.self)
            .sort(\.summary, .ascending)
            .all()
            
        #expect(groups.count >= 0)
    }
    
    @Test("多重连接查询 (Multi-Join)")
    func testMultiJoin() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        // Join QUserInfo -> QUser and QUserInfo -> QInfoSlice<AlternateEmail>
        let q: Query.Builder<QUserInfo> = s.origin.query(QUserInfo.self)
        let q1: Query.Builder<QUserInfo> = q.join(QUser.self, on: \QUserInfo.$user.id == \QUser.id)
        let q2: Query.Builder<QUserInfo> = q1.join(QInfoSlice<AlternateEmail>.self, on: \QUserInfo.id == \QInfoSlice<AlternateEmail>.$userInfo.id)
        let results = try await q2.all()
            
        #expect(results.count >= 0)
    }
    
    @Test("完整聚合查询 (Full Aggregate)")
    func testFullAggregate() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        // Count
        let count1 = try await s.origin.query(QUser.self).count()
        let count2 = try await s.origin.query(QUser.self).count(\.email)
        let count3 = try await s.origin.query(QUser.self).count(\.id)
        #expect(count1 >= 0 && count2 >= 0 && count3 >= 0)
        
        // 分别测试 Optional 和 非 Optional, Enum 和 非 Enum (目前 QUser 可能没 enum)
        // 找个有可选值的，比如 QGroup 的 summary (String?)
        let count4 = try await s.origin.query(QGroup.self).count(\.summary)
        #expect(count4 >= 0)

        // 测试 min/max/sum/avg (在某些可以支持的字段上比如 Int/Double，User.id 是 UUID 不行)
        // 这里用 QInfoSlice 的 order (Int16) 试试
        let minOrder = try await s.origin.query(QInfoSlice<AlternateEmail>.self).min(\.order)
        let maxOrder = try await s.origin.query(QInfoSlice<AlternateEmail>.self).max(\.order)
        print("Aggregate Order: min=\(minOrder), max=\(maxOrder)")
    }
    
    @Test("分页/Limit/Offset (All Extensions)")
    func testAllExtensions() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        let users1 = try await s.origin.query(QUser.self).limit(2).offset(1).all()
        #expect(users1.count <= 2)
        
        let users2 = try await s.origin.query(QUser.self).page(with: 2, size: 3)
        #expect(users2.metadata.per == 3)
        #expect(users2.metadata.page == 2)
    }
    
    @Test("多种排序组合 (Multiple Sorts)")
    func testMultipleSorts() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        // 排序：可选字段、正常字段
        let q = s.origin.query(QGroup.self)
            .sort(\.summary, .descending)
            .sort(\.name, .ascending)
            .sort(\.id, .descending)
            .sort(\.createdAt, .descending)
        
        let groups = try await q.all()
        #expect(groups.count >= 0)
        
        // Join 后排序
        let qJoin = s.origin.query(QUser.self)
            .join(QUserInfo.self, on: \QUser.id == \QUserInfo.$user.id)
            .sort(QUserInfo.self, \.identifier, .ascending)
            .sort(QUserInfo.self, \.nickname, .descending)
            
        let joinRes = try await qJoin.all()
        #expect(joinRes.count >= 0)
    }
    
    @Test("字符串操作符与数组操作符 (Operators)")
    func testOperators() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        let containsUser = try await s.origin.query(QUser.self)
            .filter(\.email ~~ "user") // Anywhere
            .filter(\.email =~ "user") // Prefix
            .filter(\.email ~= "com")  // Suffix
            .filter(\.email !~ "nonexistent") // Not Anywhere
            .filter(\.email !=~ "nonexistent") // Not Prefix
            .filter(\.email !~= "nonexistent") // Not Suffix
            .all()
        #expect(containsUser.count >= 0)
        
        // Optional String
        let descFilter = try await s.origin.query(QGroup.self)
            .filter(\.summary ~~ "a")
            .filter(\.summary =~ "a")
            .filter(\.summary ~= "a")
            .filter(\.summary !~ "non")
            .filter(\.summary !=~ "non")
            .filter(\.summary !~= "non")
            .all()
        #expect(descFilter.count >= 0)
        
        // Array filter
        let userIDs = containsUser.map { $0.id }
        if !userIDs.isEmpty {
            let inArray = try await s.origin.query(QUser.self)
                .filter(\.id ~~ userIDs)
                .all()
            #expect(inArray.count > 0)
            
            // Not in array
            let notInArray = try await s.origin.query(QUser.self)
                .filter(\.id !~ userIDs)
                .all()
            #expect(notInArray.count >= 0)
        }
    }
    
    @Test("DomainController closure & async API")
    func testDomainConcurrency() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        let users = try await s.origin.query(QUser.self).limit(1).all()
        let groups = try await s.origin.query(QGroup.self).limit(1).all()
        guard let user = users.first, let group = groups.first else { return }
        
        // create domain
        _ = try await s.domain.create(domains: [PDomain(name: "TempDomain", summary: "Temp")])
        
        let tempDomain = try await s.origin.query(QDomain.self).filter(\.name == "TempDomain").first()!
        
        // assign closure & async
        try await s.domain.assign(domainToUser: [MTMRelation(left: [tempDomain.id], right: [user.id])])
        try await s.domain.assign(domainToGroup: [MTMRelation(left: [tempDomain.id], right: [group.id])])
        
        // unassign
        try await s.domain.unassign(domainFromUser: [MTMRelation(left: [tempDomain.id], right: [user.id])])
        try await s.domain.unassign(domainFromGroup: [MTMRelation(left: [tempDomain.id], right: [group.id])])
    }
    
    @Test("RoleController closure & async API")
    func testRoleConcurrency() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        let users = try await s.origin.query(QUser.self).limit(1).all()
        let groups = try await s.origin.query(QGroup.self).limit(1).all()
        guard let user = users.first, let group = groups.first else { return }
        
        // create closure
        _ = try await s.role.create(roles: [PRole(name: "TempRole", summary: "Temp")])
        
        let tempRole = try await s.origin.query(QRole.self).filter(\.name == "TempRole").first()!
        
        // appoint closure
        try await s.role.appoint(roleToUser: [MTMRelation(left: [tempRole.id], right: [user.id])])
        try await s.role.appoint(roleToGroup: [MTMRelation(left: [tempRole.id], right: [group.id])])
        
        // appoint to userInGroup (for async coverage)
        let utgs = try await s.origin.query(UserTGroup.self).all()
        var targetUtgId: UUID? = nil
        for utg in utgs {
            if utg.userId == user.id && utg.groupId == group.id {
                targetUtgId = utg.id
                break
            }
        }
        if let utgId = targetUtgId {
            try await s.role.appoint(roleToUserInGroup: [MTMRelation(left: [tempRole.id], right: [utgId])])
            try await s.role.dismiss(roleFromUserInGroup: [MTMRelation(left: [tempRole.id], right: [utgId])])
        }
        
        // dismiss
        try await s.role.dismiss(roleFromUser: [MTMRelation(left: [tempRole.id], right: [user.id])])
        try await s.role.dismiss(roleFromGroup: [MTMRelation(left: [tempRole.id], right: [group.id])])
    }
    
    @Test("GroupController async API")
    func testGroupConcurrency() async throws {
        let (s, _) = try await TestingShared.getSystem()
        
        let users = try await s.origin.query(QUser.self).limit(1).all()
        guard let user = users.first else { return }
        
        // create closure
        _ = try await s.group.create(groups: [PGroup(name: "TempGroup", parentId: nil, summary: "Temp")])
        
        let tempGroup = try await s.origin.query(QGroup.self).filter(\.name == "TempGroup").first()!
        
        // add users
        try await s.group.join(userToGroup: [MTMRelation(left: [user.id], right: [tempGroup.id])])
        try await s.group.kick(userFromGroup: [MTMRelation(left: [user.id], right: [tempGroup.id])])
    }
    
    @MainActor
    @Test("测试结束")
    func end() async throws {
        TestingShared.testStage = .init(rawValue: TestingShared.testStage.rawValue + 1)!
    }
}
