import Foundation
import PrivilegeModule

public struct PGroup: DTO.Prepare {
    public typealias QueriedModel = QGroup
    public let id: UUID?
    public let name: String
    public let parentId: UUID?
    public let summary: String?
    
    public static let logName: String = "PGroup"
    
    public init(
        id: UUID? = nil,
        under parent: QGroup?,
        name: String,
        summary: String? = nil
    ) {
        self = Self.init(id: id, name: name, parentId: parent?.id, summary: summary)
    }
    
    public init(
        id: UUID? = nil,
        name: String,
        parentId: UUID? = nil,
        summary: String? = nil
    ) {
        self.id = id
        self.parentId = parentId
        self.name = name
        self.summary = summary
    }
    
    public var maps: [CodingKeys: AnyHashable?] {[
        .id: .init(obj: self.id),
        .name: .init(obj: self.name),
        .parentId: .init(obj: self.parentId),
        .summary: .init(obj: self.summary)
    ]}
    
    public var summaryKeys: [CodingKeys] { [.id, .name] }
    
    public enum CodingKeys: String, DTO.CodingKey {
        case id
        case name
        case parentId = "parent_id"
        case summary
    }
}

public struct QGroup: DTO.Queried {
    public typealias PrepareModel = PGroup
    public let id: UUID
    public let name: String
    public let summary: String?
    public let createdAt: Date
    public let updatedAt: Date
    
    @OptionalSuper                      public var parent: QGroup?
    @Subs(for: \.$parent)               public var childs: [QGroup]
    
    @Sibling(
        through: UserTGroup.self,
        from: \.groupId,
        to: \.userId
    )                                   public var users: [QUser]
    
    @Sibling(
        through: RoleTGroup.self,
        from: \.groupId,
        to: \.roleId
    )                                   public var roles: [QRole]
    
    @Sibling(
        through: DomainTGroup.self,
        from: \.groupId,
        to: \.domainId
    )                                   public var domains: [QDomain]
    
    public static let logName: String = "QGroup"
    
    package let __m: __SDBM.Group?
    package static let idProperty: KeyPath<SQLModel, IDProperty<SQLModel, UUID>> = \.$id
    
    public var maps: [CodingKeys: AnyHashable?] {[
        .id: .init(obj: self.id),
        .name: .init(obj: self.name),
        .parentId: .init(obj: self.$parent.id),
        .summary: .init(obj: self.summary),
        .createdAt: .init(obj: self.createdAt),
        .updatedAt: .init(obj: self.updatedAt),
        
        .parent: .init(obj: self.$parent),
        .childs: .init(obj: self.$childs),
        .users: .init(obj: self.$users),
        .roles: .init(obj: self.$roles),
        .domains: .init(obj: self.$domains)
    ]}
    
    public var summaryKeys: [CodingKeys] { [.id, .name] }
    
    public enum CodingKeys: String, DTO.CodingKey {
        case id
        case name
        case parentId = "parent_id"
        case summary
        case createdAt = "created_at"
        case updatedAt = "updated_at"
        
        case parent
        case childs
        case users
        case roles
        case domains
    }
    
    init(
        id: UUID,
        name: String,
        parentId: UUID?,
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
        
        self.$parent.set(id: parentId)
        self.$childs.fromId = id
        self.$users.fromId = id
        self.$roles.fromId = id
        self.$domains.fromId = id
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self = Self.init(
            id: try container.decode(UUID.self, forKey: .id),
            name: try container.decode(String.self, forKey: .name),
            parentId: try container.decodeIfPresent(UUID.self, forKey: .parentId),
            summary: try container.decodeIfPresent(String.self, forKey: .summary),
            createdAt: try container.decode(Date.self, forKey: .createdAt),
            updatedAt: try container.decode(Date.self, forKey: .updatedAt),
            model: nil
        )
        
        try self.$parent.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .parent))
        try self.$childs.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .childs))
        try self.$users.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .users))
        try self.$roles.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .roles))
        try self.$domains.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .domains))
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.id, forKey: .id)
        try container.encode(self.name, forKey: .name)
        try container.encodeIfPresent(self.$parent.id, forKey: .parentId)
        try container.encodeIfPresent(self.summary, forKey: .summary)
        try container.encode(self.createdAt, forKey: .createdAt)
        try container.encode(self.updatedAt, forKey: .updatedAt)
        
        try container.encode(self.$parent, forKey: .parent)
        try container.encode(self.$childs, forKey: .childs)
        try container.encode(self.$users, forKey: .users)
        try container.encode(self.$roles, forKey: .roles)
        try container.encode(self.$domains, forKey: .domains)
    }
}

extension PGroup: __Prepare {
    package func raw() -> SQLModel {
        let group = SQLModel()
        group.id = id
        group.$parent.id = parentId
        group.name = name
        group.summary = summary
        return group
    }
}

extension QGroup: __Queried {
    package typealias Failure = PrivilegeModuleExtended.Errcase
    public static func make(from model: __SDBM.Group) -> Res<Self, PrivilegeModuleExtended.Errcase> {
        .init(throws: .groupDTOFailed, category: .internal) {
            try Self.init(
                id: model.requireID(),
                name: model.name,
                parentId: model.$parent.id,
                summary: model.summary,
                createdAt: model.createdAt,
                updatedAt: model.updatedAt,
                model: model
            )
        }
    }
}

extension QGroup: Query.Queriable {
    public typealias Model = __SDBM.Group
    public typealias ErrorType = PrivilegeModuleExtended.Errcase
    public static var paths: [PartialKeyPath<Self>: PartialKeyPath<Model>] {[
        Self.idKey: \.$id,
        \.$parent.id: \.$parent.$id,
        \.name: \.$name,
        \.summary: \.$summary,
        \.id: \.$id,
        \.createdAt: \.$createdAt,
        \.updatedAt: \.$updatedAt,
    ]}
    
    public static func buildAllFields<Base>(_ builder: QueryBuilder<Base>) -> QueryBuilder<Base> where Base: FluentKit.Model {
        builder
            .field(Model.self, \.$parent.$id)
            .field(Model.self, \.$name)
            .field(Model.self, \.$summary)
            .field(Model.self, \.$id)
            .field(Model.self, \.$createdAt)
            .field(Model.self, \.$updatedAt)
    }
}

// MARK: - Updater

public extension PGroup {
    struct Updater: @unchecked Sendable {
        public let groupId: UUID
        package var id: UUID { groupId }

        package let updates: OrderedDictionary<
            PartialKeyPath<PGroup>,
            (QueryBuilder<__SDBM.Group>, QGroup?) throws -> QueryBuilder<__SDBM.Group>
        >
        package let needsPeek: Bool

        public init(groupId: UUID) {
            self.groupId = groupId
            self.updates = [:]
            self.needsPeek = false
        }

        package init(
            id: UUID,
            updates: OrderedDictionary<
                PartialKeyPath<PGroup>,
                (QueryBuilder<__SDBM.Group>, QGroup?) throws -> QueryBuilder<__SDBM.Group>
            >,
            needsPeek: Bool
        ) {
            self.groupId = id
            self.updates = updates
            self.needsPeek = needsPeek
        }
    }
}

extension PGroup.Updater: DTOUpdater {}

public extension PGroup.Updater {
    func update(name: @escaping @autoclosure () throws -> String) -> Self {
        generate(key: \.name) { builder, _ in
            builder.set(\.$name, to: try name())
        }
    }

    func update(summary: @escaping @autoclosure () throws -> String?) -> Self {
        generate(key: \.summary) { builder, _ in
            builder.set(\.$summary, to: try summary())
        }
    }
}

public extension PGroup.Updater {
    func update(name: @escaping (QGroup) throws -> String) -> Self {
        generate(needsPeek: true, key: \.name) { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$name, to: try name(q))
        }
    }

    func update(summary: @escaping (QGroup) throws -> String?) -> Self {
        generate(needsPeek: true, key: \.summary) { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$summary, to: try summary(q))
        }
    }
}

public extension QGroup {
    static func testMake(
        id: UUID,
        name: String,
        summary: String? = nil,
        parent: TestingRelation<QGroup?, UUID>,
        childs: TestingRelation<[QGroup], Void> = .unset(()),
        users: TestingRelation<[QUser], Void> = .unset(()),
        roles: TestingRelation<[QRole], Void> = .unset(()),
        domains: TestingRelation<[QDomain], Void> = .unset(()),
        createdAt: Date = .init(),
        updatedAt: Date = .init()
    ) -> Self {
        let parentId = switch parent {
        case .unset(let uuid): uuid
        case .set(let p): p?.id
        }
        
        let group = QGroup(
            id: id,
            name: name,
            parentId: parentId,
            summary: summary,
            createdAt: createdAt,
            updatedAt: updatedAt,
            model: nil
        )
        
        group.$parent.setIfNeed(to: parent)
        group.$childs.setIfNeed(to: childs)
        group.$users.setIfNeed(to: users)
        group.$roles.setIfNeed(to: roles)
        group.$domains.setIfNeed(to: domains)
        
        return group
    }
}
