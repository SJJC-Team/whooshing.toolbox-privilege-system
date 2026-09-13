import Foundation
import PrivilegeModule

public typealias PAddressSlice = PInfoSlice<Address>
public typealias QAddressSlice = QInfoSlice<Address>

public typealias PAlternateEmailSlice = PInfoSlice<AlternateEmail>
public typealias QAlternateEmailSlice = QInfoSlice<AlternateEmail>

public typealias PPhoneSlice = PInfoSlice<Phone>
public typealias QPhoneSlice = QInfoSlice<Phone>

public typealias PExtendedSlice<T: UserInfoModel> = PInfoSlice<T>
public typealias QExtendedSlice<T: UserInfoModel> = QInfoSlice<T>

public struct PInfoSlice<G: UserInfoModel>: DTO.Prepare {
    public typealias QueriedModel = QInfoSlice<G>
    public let id: UUID?
    public let value: G.Model.Value
    public let order: Int16
    public let summary: String?
    
    public static var logName: String { "PInfoSlice" }
    
    public init(
        id: UUID? = nil,
        value: G.Model.Value,
        order: Int16,
        summary: String? = nil
    ) {
        self.id = id
        self.value = value
        self.order = order
        self.summary = summary
    }
    
    public var maps: [CodingKeys: AnyHashable?] {[
        .id: self.id,
        .value: self.value,
        .order: self.order,
        .summary: self.summary
    ]}
    
    public var summaryKeys: [CodingKeys] { [.id, .value, .order] }
    
    public enum CodingKeys: String, DTO.CodingKey {
        case id
        case value
        case order
        case summary
    }
}

public struct QInfoSlice<G: UserInfoModel>: DTO.Queried {
    public typealias PrepareModel = PInfoSlice<G>
    public let id: UUID
    public let value: G.Model.Value
    public let order: Int16
    public let summary: String?
    public let createdAt: Date
    public let updatedAt: Date
    
    @Super public var userInfo: QUserInfo
    
    public static var logName: String { "QInfoSlice" }
    
    package let __m: __SDBM.User.Info.Extended<G.Model>?
    package static var idProperty: KeyPath<SQLModel, IDProperty<SQLModel, UUID>> { \.$id }
    
    public var maps: [CodingKeys: AnyHashable?] {[
        .id: .init(obj: self.id),
        .userInfoId: .init(obj: self.$userInfo.id),
        .value: .init(obj: self.value),
        .order: .init(obj: self.order),
        .summary: .init(obj: self.summary),
        .createdAt: .init(obj: self.createdAt),
        .updatedAt: .init(obj: self.updatedAt),
        
        .userInfo: .init(obj: self.$userInfo)
    ]}
    
    public var summaryKeys: [CodingKeys] { [.id, .value, .order] }
    
    public enum CodingKeys: String, DTO.CodingKey {
        case id
        case userInfoId = "user_info_id"
        case value
        case order
        case summary
        case createdAt = "created_at"
        case updatedAt = "updated_at"
        
        case userInfo = "user_info"
    }
    
    init(
        id: UUID,
        userInfoId: UUID,
        value: G.Model.Value,
        order: Int16,
        summary: String?,
        createdAt: Date,
        updatedAt: Date,
        model: SQLModel?
    ) {
        self.id = id
        self.value = value
        self.order = order
        self.summary = summary
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.__m = model
        
        self.$userInfo.set(id: userInfoId)
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self = Self.init(
            id: try container.decode(UUID.self, forKey: .id),
            userInfoId: try container.decode(UUID.self, forKey: .userInfoId),
            value: try container.decode(G.Model.Value.self, forKey: .value),
            order: try container.decode(Int16.self, forKey: .order),
            summary: try container.decodeIfPresent(String.self, forKey: .summary),
            createdAt: try container.decode(Date.self, forKey: .createdAt),
            updatedAt: try container.decode(Date.self, forKey: .updatedAt),
            model: nil
        )
        
        try self.$userInfo.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .userInfo))
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: QInfoSlice<G>.CodingKeys.self)
        try container.encode(self.id, forKey: .id)
        try container.encode(self.$userInfo.id, forKey: .userInfoId)
        try container.encode(self.value, forKey: .value)
        try container.encode(self.order, forKey: .order)
        try container.encodeIfPresent(self.summary, forKey: .summary)
        try container.encode(self.createdAt, forKey: .createdAt)
        try container.encode(self.updatedAt, forKey: .updatedAt)
        
        try container.encode(self.$userInfo, forKey: .userInfo)
    }
}

extension PInfoSlice: __Prepare {
    package func raw(for userInfoId: UUID) -> SQLModel {
        let info = SQLModel()
        info.id = id
        info.$userInfo.id = userInfoId
        info.value = value
        info.order = order
        info.summary = summary
        return info
    }
}

extension QInfoSlice: __Queried {
    package typealias Failure = PrivilegeModuleExtended.Errcase
    public static func make(from model: __SDBM.User.Info.Extended<G.Model>) -> Res<Self, PrivilegeModuleExtended.Errcase> {
        .init(throws: .userInfoDTOFailed, category: .internal) {
            try Self.init(
                id: model.requireID(),
                userInfoId: model.$userInfo.id,
                value: model.value,
                order: model.order,
                summary: model.summary,
                createdAt: model.createdAt,
                updatedAt: model.updatedAt,
                model: model
            )
        }
    }
}

extension QInfoSlice: Query.Queriable {
    public typealias Model = __SDBM.User.Info.Extended<G.Model>
    public typealias ErrorType = PrivilegeModuleExtended.Errcase
    public static var paths: [PartialKeyPath<Self>: PartialKeyPath<Model>] {[
        Self.idKey: \.$id,
        \.value: \.$value,
        \.order: \.$order,
        \.summary: \.$summary,
        \.id: \.$id,
        \.$userInfo.id: \.$userInfo.$id,
        \.createdAt: \.$createdAt,
        \.updatedAt: \.$updatedAt
    ]}
    
    public static func buildAllFields<Base>(_ builder: QueryBuilder<Base>) -> QueryBuilder<Base> where Base: FluentKit.Model {
        builder
            .field(Model.self, \.$value)
            .field(Model.self, \.$order)
            .field(Model.self, \.$summary)
            .field(Model.self, \.$id)
            .field(Model.self, \.$userInfo.$id)
            .field(Model.self, \.$createdAt)
            .field(Model.self, \.$updatedAt)
    }
}

// MARK: - User Info Models

public protocol UserInfoModel: Sendable {
    associatedtype Model: UserInfoExtends.Model
    static var summary: String { get }
}

public struct Address: UserInfoModel {
    public typealias Model = UserInfoExtends.Address
    public static let summary = "地址"
}

public struct AlternateEmail: UserInfoModel {
    public typealias Model = UserInfoExtends.AlternateEmail
    public static let summary = "次要邮箱"
}

public struct Phone: UserInfoModel {
    public typealias Model = UserInfoExtends.Phone
    public static let summary = "次要手机号"
}

// MARK: - Updater

public extension PInfoSlice {
    struct Updater: @unchecked Sendable {
        public let infoSliceId: UUID
        package var id: UUID { infoSliceId }

        package let updates: OrderedDictionary<
            PartialKeyPath<PInfoSlice<G>>,
            (QueryBuilder<__SDBM.User.Info.Extended<G.Model>>, QInfoSlice<G>?) throws -> QueryBuilder<__SDBM.User.Info.Extended<G.Model>>
        >
        package let needsPeek: Bool

        public init(infoSliceId: UUID) {
            self.infoSliceId = infoSliceId
            self.updates = [:]
            self.needsPeek = false
        }

        package init(
            id: UUID,
            updates: OrderedDictionary<
                PartialKeyPath<PInfoSlice<G>>,
                (QueryBuilder<__SDBM.User.Info.Extended<G.Model>>, QInfoSlice<G>?) throws -> QueryBuilder<__SDBM.User.Info.Extended<G.Model>>
            >,
            needsPeek: Bool
        ) {
            self.infoSliceId = id
            self.updates = updates
            self.needsPeek = needsPeek
        }
    }
}

extension PInfoSlice.Updater: DTOUpdater {}

public extension PInfoSlice.Updater {
    func update(value: @escaping @autoclosure () throws -> G.Model.Value) -> Self {
        generate(key: \.value) { builder, _ in
            builder.set(\.$value, to: try value())
        }
    }

    func update(order: @escaping @autoclosure () throws -> Int16) -> Self {
        generate(key: \.order) { builder, _ in
            builder.set(\.$order, to: try order())
        }
    }

    func update(summary: @escaping @autoclosure () throws -> String?) -> Self {
        generate(key: \.summary) { builder, _ in
            builder.set(\.$summary, to: try summary())
        }
    }
}

public extension PInfoSlice.Updater {
    func update(value: @escaping (QInfoSlice<G>) throws -> G.Model.Value) -> Self {
        generate(needsPeek: true, key: \.value) { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$value, to: try value(q))
        }
    }

    func update(order: @escaping (QInfoSlice<G>) throws -> Int16) -> Self {
        generate(needsPeek: true, key: \.order) { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$order, to: try order(q))
        }
    }

    func update(summary: @escaping (QInfoSlice<G>) throws -> String?) -> Self {
        generate(needsPeek: true, key: \.summary) { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$summary, to: try summary(q))
        }
    }
}

public extension QInfoSlice {
    static func testMake(
        id: UUID,
        value: G.Model.Value,
        order: Int16,
        summary: String? = nil,
        userInfo: TestingRelation<QUserInfo, UUID>,
        createdAt: Date = .init(),
        updatedAt: Date = .init()
    ) -> Self {
        let userInfoId = switch userInfo {
        case .unset(let uuid): uuid
        case .set(let userInfo): userInfo.id
        }
        
        let infoSlice = QInfoSlice(
            id: id,
            userInfoId: userInfoId,
            value: value,
            order: order,
            summary: summary,
            createdAt: createdAt,
            updatedAt: updatedAt,
            model: nil
        )
        
        infoSlice.$userInfo.setIfNeed(to: userInfo)
        
        return infoSlice
    }
}
