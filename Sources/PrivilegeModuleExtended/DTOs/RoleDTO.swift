import Vapor
import Foundation
import PrivilegeModule

public struct PRole: DTO.Prepare {
    public typealias QueriedModel = QRole
    public let id: UUID?
    public let name: String
    public let summary: String?
    
    public static let logName: String = "PRole"
    
    public init(
        id: UUID? = nil,
        name: String,
        summary: String? = nil
    ) {
        self.id = id
        self.name = name
        self.summary = summary
    }
    
    public var maps: [CodingKeys: AnyHashable?] {[
        .id: .init(obj: self.id),
        .name: .init(obj: self.name),
        .summary: .init(obj: self.summary)
    ]}
    
    public var summaryKeys: [CodingKeys] { [.id, .name] }
    
    public enum CodingKeys: String, DTO.CodingKey {
        case id
        case name
        case summary
    }
}

public struct QRole: DTO.Queried {
    public typealias PrepareModel = PRole
    public let id: UUID
    public let name: String
    public let summary: String?
    public let createdAt: Date
    public let updatedAt: Date
    
    @Sibling(
        through: UserTRole.self,
        from: \.roleId,
        to: \.userId
    )                                               public var users: [QUser]
    
    @Sibling(
        through: RoleTGroup.self,
        from: \.roleId,
        to: \.groupId
    )                                               public var groups: [QGroup]
    
    @Sibling(
        through: RoleTUserInGroup.self,
        from: \.roleId,
        to: \.userInGroupId
    )                                               public var userInGroups: [UserTGroup]
    
    @Subs(for: \.$parent)                           public var policies: [QPolicy<Role>]
    
    public static let logName: String = "QRole"
    
    package let __m: __SDBM.Role?
    package static let idProperty: KeyPath<SQLModel, IDProperty<SQLModel, UUID>> = \.$id
    
    public var maps: [CodingKeys: AnyHashable?] {[
        .id: .init(obj: self.id),
        .name: .init(obj: self.name),
        .summary: .init(obj: self.summary),
        .createdAt: .init(obj: self.createdAt),
        .updatedAt: .init(obj: self.updatedAt),
        
        .users: .init(obj: self.$users),
        .groups: .init(obj: self.$groups),
        .userInGroups: .init(obj: self.$userInGroups),
        .policies: .init(obj: self.$policies)
    ]}
    
    public var summaryKeys: [CodingKeys] { [.id, .name] }
    
    public enum CodingKeys: String, DTO.CodingKey {
        case id
        case name
        case summary
        case createdAt = "created_at"
        case updatedAt = "updated_at"
        
        case users
        case groups
        case userInGroups = "user_in_groups"
        case policies
    }
    
    init(
        id: UUID,
        name: String,
        summary: String?,
        createdAt: Date,
        updatedAt: Date,
        model: SQLModel?
    ) {
        self.id = id
        self.name = name
        self.summary = summary
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.__m = model
        
        self.$users.fromId = id
        self.$groups.fromId = id
        self.$userInGroups.fromId = id
        self.$policies.fromId = id
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self = Self.init(
            id: try container.decode(UUID.self, forKey: .id),
            name: try container.decode(String.self, forKey: .name),
            summary: try container.decodeIfPresent(String.self, forKey: .summary),
            createdAt: try container.decode(Date.self, forKey: .createdAt),
            updatedAt: try container.decode(Date.self, forKey: .updatedAt),
            model: nil
        )
        
        try self.$users.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .users))
        try self.$groups.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .groups))
        try self.$userInGroups.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .userInGroups))
        try self.$policies.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .policies))
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encodeIfPresent(summary, forKey: .summary)
        try container.encode(self.createdAt, forKey: .createdAt)
        try container.encode(self.updatedAt, forKey: .updatedAt)
        
        try container.encode(self.$users, forKey: .users)
        try container.encode(self.$groups, forKey: .groups)
        try container.encode(self.$userInGroups, forKey: .userInGroups)
        try container.encode(self.$policies, forKey: .policies)
    }
}

extension PRole: __Prepare {
    /// 需要先存 Policy 到数据库中
    package func raw() -> SQLModel {
        let role = SQLModel()
        role.id = id
        role.name = name
        role.summary = summary
        return role
    }
}

extension QRole: __Queried {
    package typealias Failure = PrivilegeModuleExtended.Errcase
    public static func make(from model: __SDBM.Role) -> Res<Self, PrivilegeModuleExtended.Errcase> {
        .init(throws: .roleDTOFailed, category: .internal) {
            try Self.init(
                id: model.requireID(),
                name: model.name,
                summary: model.summary,
                createdAt: model.createdAt,
                updatedAt: model.updatedAt,
                model: model
            )
        }
    }
}

extension QRole: Query.Queriable {
    public typealias Model = __SDBM.Role
    public typealias ErrorType = PrivilegeModuleExtended.Errcase
    public static var paths: [PartialKeyPath<Self>: PartialKeyPath<Model>] {[
        Self.idKey: \.$id,
        \.name: \.$name,
        \.summary: \.$summary,
        \.id: \.$id,
        \.createdAt: \.$createdAt,
        \.updatedAt: \.$updatedAt
    ]}
    
    public static func buildAllFields<Base>(_ builder: QueryBuilder<Base>) -> QueryBuilder<Base> where Base: FluentKit.Model {
        builder
            .field(Model.self, \.$name)
            .field(Model.self, \.$summary)
            .field(Model.self, \.$id)
            .field(Model.self, \.$createdAt)
            .field(Model.self, \.$updatedAt)
    }
}

// MARK: - Updater

public extension PRole {
    class Updater: @unchecked Sendable {
        public let roleId: UUID
        package var id: UUID { roleId }
        package var reservedRoleNames: [String]? {
            get {
                lock.withLock { __reservedRoleNames }
            }
            set {
                lock.withLock { __reservedRoleNames = newValue }
            }
        }
        
        private var __reservedRoleNames: [String]? = nil
        private let lock = NIOLock()
        
        package private(set) var updates: OrderedDictionary<
            PartialKeyPath<PRole>,
            (QueryBuilder<__SDBM.Role>, QRole?) throws -> QueryBuilder<__SDBM.Role>
        >
        package private(set) var needsPeek: Bool
        
        public init(roleId: UUID) {
            self.roleId = roleId
            self.updates = [:]
            self.needsPeek = false
        }
        
        required package init(
            id: UUID,
            updates: OrderedDictionary<
                PartialKeyPath<PRole>,
                (QueryBuilder<__SDBM.Role>, QRole?) throws -> QueryBuilder<__SDBM.Role>
            >,
            needsPeek: Bool
        ) {
            self.roleId = id
            self.updates = updates
            self.needsPeek = needsPeek
        }
    }
}

extension PRole.Updater: DTOUpdater {}

public extension PRole.Updater {
    func update(name: @escaping @autoclosure () throws -> String) -> Self {
        updates[\.name] = { builder, _ in
            let roleName = try name()
            
            guard let rNames = self.reservedRoleNames else {
                throw PrivilegeModuleExtended.Errcase.roleNameIlligel.d("业务流程出错，角色名称保留字 reservedRoleNames 未设置", category: .internal)
            }
            guard !rNames.contains(roleName) else {
                throw PrivilegeModuleExtended.Errcase.roleNameIlligel.d("\"\(roleName)\" 为角色保留名，不可作为角色名", category: .external(suggestions: ["请选择非保留字的名称作为角色名称"], userdata: .init(HTTPResponseStatus.unprocessableEntity)))
            }
            
            return builder.set(\.$name, to: roleName)
        }
        
        return self
    }
    
    func update(summary: @escaping @autoclosure () throws -> String?) -> Self {
        updates[\.summary] = { builder, _ in
            builder.set(\.$summary, to: try summary())
        }
        
        return self
    }
}

public extension PRole.Updater {
    func update(name: @escaping (QRole) throws -> String) -> Self {
        updates[\.name] = { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            
            let roleName = try name(q)
            
            guard let rNames = self.reservedRoleNames else {
                throw PrivilegeModuleExtended.Errcase.roleNameIlligel.d("业务流程出错，角色名称保留字 reservedRoleNames 未设置", category: .internal)
            }
            guard !rNames.contains(roleName) else {
                throw PrivilegeModuleExtended.Errcase.roleNameIlligel.d("\"\(roleName)\" 为角色保留名，不可作为角色名", category: .external(suggestions: ["请选择非保留字的名称作为角色名称"], userdata: .init(HTTPResponseStatus.unprocessableEntity)))
            }
            
            return builder.set(\.$name, to: roleName)
        }
        
        self.needsPeek = true
        
        return self
    }
    
    func update(summary: @escaping (QRole) throws -> String?) -> Self {
        updates[\.summary] = { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$summary, to: try summary(q))
        }
        
        self.needsPeek = true
        
        return self
    }
}

extension QRole: Authenticatable {}

public extension QRole {
    static func testMake(
        id: UUID,
        name: String,
        summary: String? = nil,
        users: TestingRelation<[QUser], Void> = .unset(()),
        groups: TestingRelation<[QGroup], Void> = .unset(()),
        userInGroups: TestingRelation<[UserTGroup], Void> = .unset(()),
        policies: TestingRelation<[QPolicy<Role>], Void> = .unset(()),
        createdAt: Date = .init(),
        updatedAt: Date = .init()
    ) -> Self {
        let role = QRole(
            id: id,
            name: name,
            summary: summary,
            createdAt: createdAt,
            updatedAt: updatedAt,
            model: nil
        )
        
        role.$users.setIfNeed(to: users)
        role.$groups.setIfNeed(to: groups)
        role.$userInGroups.setIfNeed(to: userInGroups)
        role.$policies.setIfNeed(to: policies)
        
        return role
    }
}
