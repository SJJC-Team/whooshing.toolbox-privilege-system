import PgSQL
import Foundation

/// 拥有 OPA 策略的模型类型。
///
/// `Role`、`Domain` 和模块内的 `Privilege` Model 都会实现 `PolicyType`。
/// 该协议提供策略表命名和 OPA 路径所需的元数据，供 `PolicyExp` 和策略控制器使用。
public protocol PolicyType: Sendable where Model.IDValue == UUID {
    associatedtype DTOModel: DTO.DBModel
    /// 拥有策略行的 Fluent Model。
    associatedtype Model: PGModel
    /// 策略表和外键字段使用的数据库前缀。
    static var namePrefix: String { get }
    /// 标识策略类别的 OPA 路径片段。
    static var typeId: String { get }
}

public extension __SDBM {
    final class PolicyExp<T: PolicyType>: PGModel, @unchecked Sendable {
        
        public static var name: String { T.namePrefix + "_policies" }
        
        public struct Fields: PGFields {
            public let id = PGField("id", .uuid)                            .primary
            public let parentId = PGField("\(T.namePrefix)_id", .uuid)      .required.foreign(T.Model.self, .id, onDelete: .cascade)
            public let moduleId = PGField("module_id", .uuid)               .required
            public let policy = PGField("policy", .string)                  .required
            public let createdAt = PGField("created_at", .datetime)         .required
            public let updatedAt = PGField("updated_at", .datetime)         .required
            
            public init() {}
        }
        
        let fields = Fields()
        
        @ID(key: .id)                                   public var id: UUID?
        
        @Parent(fields.parentId)                        public var parent: T.Model
        @Field(fields.moduleId)                         public var moduleId: UUID
        @Field(fields.policy)                           public var policy: String
        @Timestamp(fields.createdAt, on: .create)       public var createdAt: Date!
        @Timestamp(fields.updatedAt, on: .update)       public var updatedAt: Date!
        
        public init() {}
        
        public typealias MIG = DefaultMIG<PolicyExp<T>>
    }
}

package enum PathFormat: Sendable {
    case path
    case route
    
    var prefix: String {
        switch self {
        case .path: "/"
        case .route: ""
        }
    }
    
    var sign: String {
        switch self {
        case .path: "/"
        case .route: "."
        }
    }
}

package func policyPath<PT: PolicyType>(
    moduleId: UUID,
    modelId: UUID?,
    policyId: UUID,
    type: PT.Type = PT.self,
    format: PathFormat
) -> String {
    policyPath(moduleId: moduleId, modelId: modelId, policyId: policyId, type: PT.typeId, format: format)
}

package func policyPath(
    moduleId: UUID,
    modelId: UUID?,
    policyId: UUID,
    type: String,
    format: PathFormat
) -> String {
    var components = [
        "\(format.prefix)m_\(moduleId.hexString)",
        type
    ]
    
    if let modelId = modelId {
        components.append("v_\(modelId.hexString)")
    }
    
    components.append("p_\(policyId.hexString)")
    
    return components.joined(separator: format.sign)
}

package func assemblePolicy(
    path: String,
    policy: String
) -> String {
    """
    package rules.\(path)
    import data.utils.pg
    default allow := false
    
    \(policy)
    """
}
