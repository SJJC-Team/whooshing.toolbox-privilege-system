import Foundation
import PrivilegeModule

public struct PPolicy<G: PolicyType>: DTO.Prepare {
    public typealias QueriedModel = QPolicy<G>
    public let id: UUID?
    public let moduleId: UUID
    public let policy: String
    
    public static var logName: String { "PPolicy<\(G.typeId.uppercased())>" }
    
    public init(
        id: UUID? = nil,
        moduleId: UUID,
        policy: String
    ) {
        self.id = id
        self.moduleId = moduleId
        self.policy = policy
    }
    
    public var maps: [CodingKeys: AnyHashable?] {[
        .id: .init(obj: self.id),
        .moduleId: .init(obj: self.moduleId),
        .policy: .init(obj: self.policy)
    ]}
    
    public var summaryKeys: [CodingKeys] { [.id, .moduleId] }
    
    public enum CodingKeys: String, DTO.CodingKey {
        case id
        case moduleId = "module_id"
        case policy
    }
    
    public func set(id: UUID) -> Self {
        .init(
            id: id,
            moduleId: self.moduleId,
            policy: self.policy
        )
    }
}

public struct QPolicy<G: PolicyType>: DTO.Queried {
    public typealias PrepareModel = PPolicy<G>
    public let id: UUID
    public let moduleId: UUID
    public let policy: String
    public let createdAt: Date
    public let updatedAt: Date
    
    @Super public var parent: G.DTOModel
    
    public static var logName: String { "QPolicy<\(G.typeId.uppercased())>" }
    
    package let __m: __SDBM.PolicyExp<G>?
    package static var idProperty: KeyPath<SQLModel, IDProperty<SQLModel, UUID>> { \.$id }
    
    public var maps: [CodingKeys: AnyHashable?] {[
        .id: .init(obj: self.id),
        .moduleId: .init(obj: self.moduleId),
        .policy: .init(obj: self.policy),
        .parentId: .init(obj: self.$parent.id),
        .createdAt: .init(obj: self.createdAt),
        .updatedAt: .init(obj: self.updatedAt),
        
        .parent: .init(obj: self.$parent)
    ]}
    
    public var summaryKeys: [CodingKeys] { [.id, .moduleId] }
    
    public enum CodingKeys: String, DTO.CodingKey {
        case id
        case moduleId = "module_id"
        case policy
        case parent
        case parentId = "parent_id"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }
    
    init(
        id: UUID,
        moduleId: UUID,
        policy: String,
        parentId: UUID,
        createdAt: Date,
        updatedAt: Date,
        model: SQLModel?
    ) {
        self.id = id
        self.moduleId = moduleId
        self.policy = policy
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.__m = model
        
        self.$parent.id = parentId
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self = Self.init(
            id: try container.decode(UUID.self, forKey: .id),
            moduleId: try container.decode(UUID.self, forKey: .moduleId),
            policy: try container.decode(String.self, forKey: .policy),
            parentId: try container.decode(UUID.self, forKey: .parentId),
            createdAt: try container.decode(Date.self, forKey: .createdAt),
            updatedAt: try container.decode(Date.self, forKey: .updatedAt),
            model: nil
        )
        
        try self.$parent.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .parent))
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: QPolicy<G>.CodingKeys.self)
        try container.encode(self.id, forKey: .id)
        try container.encode(self.moduleId, forKey: .moduleId)
        try container.encode(self.policy, forKey: .policy)
        try container.encode(self.$parent.id, forKey: .parentId)
        try container.encode(self.createdAt, forKey: .createdAt)
        try container.encode(self.updatedAt, forKey: .updatedAt)
        
        try container.encode(self.$parent, forKey: .parent)
    }
}

extension PPolicy: __Prepare {
    /// 需要先存 Policy 到数据库中
    package func raw(parentId: G.Model.IDValue) -> SQLModel {
        let policy = SQLModel()
        policy.id = id
        policy.$parent.id = parentId
        policy.moduleId = moduleId
        policy.policy = self.policy
        return policy
    }
}

extension QPolicy: __Queried {
    package typealias Failure = PrivilegeModuleExtended.Errcase
    public static func make(from model: __SDBM.PolicyExp<G>) -> Res<Self, PrivilegeModuleExtended.Errcase> {
        .init(throws: .policyDTORawCreateFailed, category: .internal) {
            Self.init(
                id: try model.requireID(),
                moduleId: model.moduleId,
                policy: model.policy,
                parentId: model.$parent.id,
                createdAt: model.createdAt,
                updatedAt: model.updatedAt,
                model: model
            )
        }
    }
}

extension QPolicy: Query.Queriable {
    public typealias Model = __SDBM.PolicyExp<G>
    public typealias ErrorType = PrivilegeModuleExtended.Errcase
    public static var paths: [PartialKeyPath<Self>: PartialKeyPath<Model>] {[
        Self.idKey: \.$id,
        \.$parent.id: \.$parent.$id,
        \.moduleId: \.$moduleId,
        \.policy: \.$policy,
        \.id: \.$id,
        \.createdAt: \.$createdAt,
        \.updatedAt: \.$updatedAt
    ]}
    
    public static func buildAllFields<Base>(_ builder: QueryBuilder<Base>) -> QueryBuilder<Base> where Base: FluentKit.Model {
        builder
            .field(Model.self, \.$parent.$id)
            .field(Model.self, \.$moduleId)
            .field(Model.self, \.$policy)
            .field(Model.self, \.$id)
            .field(Model.self, \.$createdAt)
            .field(Model.self, \.$updatedAt)
    }
}

public extension QPolicy {
    static func testMake(
        id: UUID,
        moduleId: UUID,
        policy: String,
        parent: TestingRelation<G.DTOModel, UUID>,
        createdAt: Date = .init(),
        updatedAt: Date = .init()
    ) -> Self {
        let parentId = switch parent {
        case .unset(let uuid): uuid
        case .set(let parent): parent.id
        }
        
        let policy = QPolicy(
            id: id,
            moduleId: moduleId,
            policy: policy,
            parentId: parentId,
            createdAt: createdAt,
            updatedAt: updatedAt,
            model: nil
        )
        
        policy.$parent.setIfNeed(to: parent)
        
        return policy
    }
}
