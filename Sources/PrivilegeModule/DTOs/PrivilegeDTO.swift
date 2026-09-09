import DTOBuilder
import Foundation

public extension PM {
    struct PPrivilege: DTO.Prepare {
        public typealias QueriedModel = QPrivilege
        public let id: UUID?
        /// 权限名称。
        public let name: String?
        /// 权限说明。
        public let summary: String?
        /// OPA 策略表达式。控制器会自动包装 package、import 和默认 allow。
        public let policy: String
        
        public static var logName: String { "PPrivilege" }
        
        /// 创建一个待保存的资源权限。
        ///
        /// ```swift
        /// let privilege = PM<ResourceList>.PPrivilegeDTO(
        ///     name: "ReadFile",
        ///     summary: "允许读取文件",
        ///     policy: "allow if { input.operation == \"read\" }"
        /// )
        /// ```
        public init(
            id: UUID? = nil,
            name: String? = nil,
            summary: String? = nil,
            policy: String
        ) {
            self.id = id
            self.name = name
            self.summary = summary
            self.policy = policy
        }
        
        public var maps: [CodingKeys: AnyHashable?] {[
            .id: .init(obj: self.id),
            .name: .init(obj: self.name),
            .summary: .init(obj: self.summary),
            .policy: .init(obj: self.policy)
        ]}
        
        public var summaryKeys: [CodingKeys] { [.id, .name] }
        
        public enum CodingKeys: String, DTO.CodingKey {
            case id
            case name
            case summary
            case policy
        }
        
        public func set(id: UUID) -> Self {
            .init(
                id: id,
                name: self.name,
                summary: self.summary,
                policy: self.policy
            )
        }
    }
    
    struct QPrivilege: DTO.Queried {
        public typealias PrepareModel = PPrivilege
        public let id: UUID
        /// 权限名称。
        public let name: String?
        /// 权限说明。
        public let summary: String?
        /// OPA 策略表达式。控制器会自动包装 package、import 和默认 allow。
        public let policy: String
        public let createdAt: Date
        public let updatedAt: Date
        
        @Sibling(
            through: PrivilegeTAnyResource.self,
            from: \.privilegeId,
            to: \.resourceId
        )                                   public var resources: [GResource]
        
        public static var logName: String { "QPrivilege" }
        
        package let __m: __DBM.Privilege?
        package static var idProperty: KeyPath<SQLModel, IDProperty<SQLModel, UUID>> { \.$id }
        
        public var maps: [CodingKeys: AnyHashable?] {[
            .id: .init(obj: self.id),
            .name: .init(obj: self.name),
            .summary: .init(obj: self.summary),
            .policy: .init(obj: self.policy),
            .createdAt: .init(obj: self.createdAt),
            .updatedAt: .init(obj: self.updatedAt),
            
            .resources: .init(obj: self.$resources)
        ]}
        
        public var summaryKeys: [CodingKeys] { [.id, .name] }
        
        public enum CodingKeys: String, DTO.CodingKey {
            case id
            case name
            case summary
            case policy
            case createdAt = "created_at"
            case updatedAt = "updated_at"
            
            case resources
        }
        
        init(
            id: UUID,
            name: String?,
            summary: String?,
            policy: String,
            createdAt: Date,
            updatedAt: Date,
            model: SQLModel?
        ) {
            self.id = id
            self.name = name
            self.summary = summary
            self.policy = policy
            self.createdAt = createdAt
            self.updatedAt = updatedAt
            self.__m = model
            
            self.$resources.fromId = id
        }
        
        public init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self = Self.init(
                id: try container.decode(UUID.self, forKey: .id),
                name: try container.decodeIfPresent(String.self, forKey: .name),
                summary: try container.decodeIfPresent(String.self, forKey: .summary),
                policy: try container.decode(String.self, forKey: .policy),
                createdAt: try container.decode(Date.self, forKey: .createdAt),
                updatedAt: try container.decode(Date.self, forKey: .updatedAt),
                model: nil
            )
            
            try self.$resources.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .resources))
        }
        
        public func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: PrivilegeModule<ResourceList>.QPrivilege.CodingKeys.self)
            try container.encode(self.id, forKey: PrivilegeModule.QPrivilege.CodingKeys.id)
            try container.encodeIfPresent(self.name, forKey: PrivilegeModule.QPrivilege.CodingKeys.name)
            try container.encodeIfPresent(self.summary, forKey: PrivilegeModule.QPrivilege.CodingKeys.summary)
            try container.encode(self.policy, forKey: PrivilegeModule.QPrivilege.CodingKeys.policy)
            try container.encode(self.createdAt, forKey: .createdAt)
            try container.encode(self.updatedAt, forKey: .updatedAt)
            
            try container.encode(self.$resources, forKey: .resources)
        }
    }
}

extension PM.PPrivilege: __Prepare {
    public typealias S = PM<ResourceList>
    func raw() -> S.__DBM.Privilege {
        let privilege = PM<ResourceList>.__DBM.Privilege()
        privilege.id = id
        privilege.name = name
        privilege.summary = summary
        privilege.policy = policy
        return privilege
    }
}

extension PM.QPrivilege: __Queried {
    public typealias S = PM<ResourceList>
    package typealias Failure = S.Errcase
    public static func make(from model: S.__DBM.Privilege) -> Res<Self, S.Errcase> {
        .init(throws: .privilegeDTOFailed, category: .internal) {
            try Self.init(
                id: model.requireID(),
                name: model.name,
                summary: model.summary,
                policy: model.policy,
                createdAt: model.createdAt,
                updatedAt: model.updatedAt,
                model: model
            )
        }
    }
}

extension PM.QPrivilege: Query.Queriable {
    public typealias Model = S.__DBM.Privilege
    public typealias ErrorType = S.Errcase
    public static var paths: [PartialKeyPath<Self>: PartialKeyPath<Model>] {[
        Self.idKey: \.$id,
        \.name: \.$name,
        \.summary: \.$summary,
        \.policy: \.$policy,
        \.id: \.$id,
        \.createdAt: \.$createdAt,
        \.updatedAt: \.$updatedAt
    ]}
    
    public static func buildAllFields<Base>(_ builder: QueryBuilder<Base>) -> QueryBuilder<Base> where Base: FluentKit.Model {
        builder
            .field(Model.self, \.$name)
            .field(Model.self, \.$summary)
            .field(Model.self, \.$policy)
            .field(Model.self, \.$id)
            .field(Model.self, \.$createdAt)
            .field(Model.self, \.$updatedAt)
    }
}

// MARK: - Updater

public extension PM.PPrivilege {
    /// 资源权限更新器。
    struct Updater: @unchecked Sendable {
        /// 要更新的资源权限 ID。
        public let privilegeId: UUID
        package var id: UUID { privilegeId }
        
        package let policyUpdate: ((S.QPrivilege?) throws -> String)?
        
        package let updates: OrderedDictionary<
            PartialKeyPath<S.PPrivilege>,
            (
                QueryBuilder<S.__DBM.Privilege>,
                S.QPrivilege?
            ) throws -> QueryBuilder<S.__DBM.Privilege>
        >
        package let needsPeek: Bool
        
        var isEmpty: Bool {
            self.updates.count == 0 && policyUpdate == nil
        }
        
        public init(privilegeId: UUID) {
            self.privilegeId = privilegeId
            self.policyUpdate = nil
            self.updates = [:]
            self.needsPeek = false
        }
        
        package init(
            id: UUID,
            policyUpdate: ((S.QPrivilege?) throws -> String)? = nil,
            updates: OrderedDictionary<
                PartialKeyPath<S.PPrivilege>,
                (QueryBuilder<S.__DBM.Privilege>, S.QPrivilege?) throws -> QueryBuilder<S.__DBM.Privilege>
            >,
            needsPeek: Bool
        ) {
            self.privilegeId = id
            self.policyUpdate = policyUpdate
            self.updates = updates
            self.needsPeek = needsPeek
        }
        
        package init(
            id: UUID,
            updates: OrderedDictionary<
                PartialKeyPath<S.PPrivilege>,
                (QueryBuilder<S.__DBM.Privilege>, S.QPrivilege?) throws -> QueryBuilder<S.__DBM.Privilege>
            >,
            needsPeek: Bool
        ) {
            self.privilegeId = id
            self.policyUpdate = nil
            self.updates = updates
            self.needsPeek = needsPeek
        }
        
        package func generate(
            needsPeek: Bool = false,
            key: PartialKeyPath<S.PPrivilege>,
            value: @escaping (QueryBuilder<S.__DBM.Privilege>, S.QPrivilege?) throws -> QueryBuilder<S.__DBM.Privilege>,
            policyUpdate: ((S.QPrivilege?) throws -> String)? = nil
        ) -> Self {
            var updates = self.updates
            updates[key] = value
            return .init(
                id: self.id,
                policyUpdate: policyUpdate ?? self.policyUpdate,
                updates: updates,
                needsPeek: self.needsPeek || needsPeek
            )
        }
    }
}

extension PM.PPrivilege.Updater: DTOUpdater {}

public extension PM.PPrivilege.Updater {
    /// 更新权限名称。
    func update(name: @escaping @autoclosure () throws -> String?) -> Self {
        generate(key: \.name) { builder, _ in
            builder.set(\.$name, to: try name())
        }
    }
    
    /// 更新权限说明。
    func update(summary: @escaping @autoclosure () throws -> String?) -> Self {
        generate(key: \.summary) { builder, _ in
            builder.set(\.$summary, to: try summary())
        }
    }
    
    /// 更新权限策略，并同步更新 OPA 中对应的策略内容。
    func update(policy: @escaping @autoclosure () throws -> String) -> Self {
        generate(
            key: \.policy,
            value: { builder, _ in
                builder.set(\.$policy, to: try policy())
            },
            policyUpdate: { _ in try policy() }
        )
    }
}

public extension PM.PPrivilege.Updater {
    typealias S = PM<ResourceList>
    /// 基于当前数据库值更新权限名称。
    func update(name: @escaping (S.QPrivilege) throws -> String?) -> Self {
        generate(needsPeek: true, key: \.name) { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$name, to: try name(q))
        }
    }
    
    /// 基于当前数据库值更新权限说明。
    func update(summary: @escaping (S.QPrivilege) throws -> String?) -> Self {
        generate(needsPeek: true, key: \.summary) { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$summary, to: try summary(q))
        }
    }
    
    /// 基于当前数据库值更新权限策略，并同步更新 OPA 中对应的策略内容。
    func update(policy: @escaping (S.QPrivilege) throws -> String) -> Self {
        generate(
            needsPeek: true,
            key: \.policy,
            value: { builder, query in
                guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
                return builder.set(\.$policy, to: try policy(q))
            },
            policyUpdate: { query in
                guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
                return try policy(q)
            }
        )
    }
}

public extension PM.QPrivilege {
    static func testMake(
        id: UUID,
        name: String? = nil,
        summary: String? = nil,
        policy: String,
        resources: TestingRelation<[GResource], Void> = .unset(()),
        createdAt: Date = .init(),
        updatedAt: Date = .init()
    ) -> Self {
        let privilege = Self(
            id: id,
            name: name,
            summary: summary,
            policy: policy,
            createdAt: createdAt,
            updatedAt: updatedAt,
            model: nil
        )
        
        privilege.$resources.setIfNeed(to: resources)
        
        return privilege
    }
}
