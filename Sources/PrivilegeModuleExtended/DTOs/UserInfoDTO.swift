import Foundation
import PrivilegeModule

public struct PUserInfo: DTO.Prepare {
    public typealias QueriedModel = QUserInfo
    public let id: UUID?
    public let nickname: String
    public let identifier: String
    public let birthday: Date
    public let other: String?
    
    public static let logName: String = "PUserInfo"
    
    public init(
        id: UUID? = nil,
        nickname: String,
        identifier: String,
        birthday: Date,
        other: String? = nil
    ) {
        self.id = id
        self.nickname = nickname
        self.identifier = identifier
        self.birthday = birthday
        self.other = other
    }
    
    public var maps: [CodingKeys: AnyHashable?] {[
        .id: .init(obj: self.id),
        .nickname: .init(obj: self.nickname),
        .identifier: .init(obj: self.identifier),
        .birthday: .init(obj: self.birthday),
        .other: .init(obj: self.other)
    ]}
    
    public var summaryKeys: [CodingKeys] { [.id] }
    
    public enum CodingKeys: String, DTO.CodingKey {
        case id
        case nickname
        case identifier
        case birthday
        case other
    }
}

public struct QUserInfo: DTO.Queried {
    public typealias PrepareModel = PUserInfo
    public let id: UUID
    public let nickname: String
    public let identifier: String
    public let birthday: Date
    public let other: String?
    public let createdAt: Date
    public let updatedAt: Date
    
    @Super public var user: QUser
    @Subs(for: \.$userInfo) public var alternateEmails: [QInfoSlice<AlternateEmail>]
    @Subs(for: \.$userInfo) public var phones: [QInfoSlice<Phone>]
    @Subs(for: \.$userInfo) public var addresses: [QInfoSlice<Address>]
    
    public static let logName: String = "PUserInfo"
    
    package let __m: __SDBM.User.Info?
    package static let idProperty: KeyPath<SQLModel, IDProperty<SQLModel, UUID>> = \.$id
    
    public var maps: [CodingKeys: AnyHashable?] {[
        .id: .init(obj: self.id),
        .userId: .init(obj: self.$user.id),
        .nickname: .init(obj: self.nickname),
        .identifier: .init(obj: self.identifier),
        .birthday: .init(obj: self.birthday),
        .other: .init(obj: self.other),
        .createdAt: .init(obj: self.createdAt),
        .updatedAt: .init(obj: self.updatedAt),
        
        .user: .init(obj: self.$user),
        .alternateEmails: .init(obj: self.$alternateEmails),
        .phones: .init(obj: self.$phones),
        .addresses: .init(obj: self.$addresses)
    ]}
    
    public var summaryKeys: [CodingKeys] { [.id] }
    
    public enum CodingKeys: String, DTO.CodingKey {
        case id
        case userId = "user_id"
        case nickname
        case identifier
        case birthday
        case other
        case createdAt = "created_at"
        case updatedAt = "updated_at"
        
        case user
        case alternateEmails = "alternate_emails"
        case phones
        case addresses
    }
    
    init(
        id: UUID,
        userId: UUID,
        nickname: String,
        identifier: String,
        birthday: Date,
        other: String?,
        createdAt: Date,
        updatedAt: Date,
        model: SQLModel?
    ) {
        self.id = id
        self.nickname = nickname
        self.identifier = identifier
        self.birthday = birthday
        self.other = other
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.__m = model
        
        self.$user.set(id: userId)
        self.$alternateEmails.fromId = id
        self.$phones.fromId = id
        self.$addresses.fromId = id
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self = Self.init(
            id: try container.decode(UUID.self, forKey: .id),
            userId: try container.decode(UUID.self, forKey: .userId),
            nickname: try container.decode(String.self, forKey: .nickname),
            identifier: try container.decode(String.self, forKey: .identifier),
            birthday: try container.decode(Date.self, forKey: .birthday),
            other: try container.decodeIfPresent(String.self, forKey: .other),
            createdAt: try container.decode(Date.self, forKey: .createdAt),
            updatedAt: try container.decode(Date.self, forKey: .updatedAt),
            model: nil
        )
        
        try self.$user.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .user))
        try self.$alternateEmails.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .alternateEmails))
        try self.$phones.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .phones))
        try self.$addresses.inject(from: container.nestedContainer(keyedBy: DTO.PropertyCodingKeys.self, forKey: .addresses))
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.id, forKey: .id)
        try container.encode(self.$user.id, forKey: .userId)
        try container.encode(self.nickname, forKey: .nickname)
        try container.encode(self.identifier, forKey: .identifier)
        try container.encode(self.birthday, forKey: .birthday)
        try container.encodeIfPresent(self.other, forKey: .other)
        try container.encode(self.createdAt, forKey: .createdAt)
        try container.encode(self.updatedAt, forKey: .updatedAt)
        
        try container.encode(self.$user, forKey: .user)
        try container.encode(self.$alternateEmails, forKey: .alternateEmails)
        try container.encode(self.$phones, forKey: .phones)
        try container.encode(self.$addresses, forKey: .addresses)
    }
}

extension PUserInfo: __Prepare {
    package func raw(for userId: UUID) -> SQLModel {
        let info = SQLModel()
        info.id = id
        info.$user.id = userId
        info.nickname = nickname
        info.identifier = identifier
        info.birthday = birthday
        info.other = other
        return info
    }
}

extension QUserInfo: __Queried {
    package typealias Failure = PrivilegeModuleExtended.Errcase
    public static func make(from model: __SDBM.User.Info) -> Res<Self, PrivilegeModuleExtended.Errcase> {
        .init(throws: .userInfoDTOFailed, category: .internal) {
            try Self.init(
                id: model.requireID(),
                userId: model.$user.id,
                nickname: model.nickname,
                identifier: model.identifier,
                birthday: model.birthday,
                other: model.other,
                createdAt: model.createdAt,
                updatedAt: model.updatedAt,
                model: model
            )
        }
    }
}

extension QUserInfo: Query.Queriable {
    public typealias Model = __SDBM.User.Info
    public typealias ErrorType = PrivilegeModuleExtended.Errcase
    public static var paths: [PartialKeyPath<Self>: PartialKeyPath<Model>] {[
        Self.idKey: \.$id,
        \.nickname: \.$nickname,
        \.identifier: \.$identifier,
        \.birthday: \.$birthday,
        \.other: \.$other,
        \.id: \.$id,
        \.$user.id: \.$user.$id,
        \.createdAt: \.$createdAt,
        \.updatedAt: \.$updatedAt
    ]}
    
    public static func buildAllFields<Base>(_ builder: QueryBuilder<Base>) -> QueryBuilder<Base> where Base: FluentKit.Model {
        builder
            .field(Model.self, \.$nickname)
            .field(Model.self, \.$identifier)
            .field(Model.self, \.$birthday)
            .field(Model.self, \.$other)
            .field(Model.self, \.$id)
            .field(Model.self, \.$user.$id)
            .field(Model.self, \.$createdAt)
            .field(Model.self, \.$updatedAt)
    }
}

// MARK: - Updater

public extension PUserInfo {
    struct Updater: @unchecked Sendable {
        public let userInfoId: UUID
        package var id: UUID { userInfoId }
        
        package let updates: OrderedDictionary<
            PartialKeyPath<PUserInfo>,
            (QueryBuilder<__SDBM.User.Info>, QUserInfo?) throws -> QueryBuilder<__SDBM.User.Info>
        >
        package let needsPeek: Bool
        
        public init(userInfoId: UUID) {
            self.userInfoId = userInfoId
            self.updates = [:]
            self.needsPeek = false
        }
        
        package init(
            id: UUID,
            updates: OrderedDictionary<
                PartialKeyPath<PUserInfo>,
                (QueryBuilder<__SDBM.User.Info>, QUserInfo?) throws -> QueryBuilder<__SDBM.User.Info>
            >,
            needsPeek: Bool
        ) {
            self.userInfoId = id
            self.updates = updates
            self.needsPeek = needsPeek
        }
    }
}

extension PUserInfo.Updater: DTOUpdater {}

public extension PUserInfo.Updater {
    func update(identifier: @escaping @autoclosure () throws -> String) -> Self {
        generate(key: \.identifier) { builder, _ in
            builder.set(\.$identifier, to: try identifier())
        }
    }
    
    func update(nickname: @escaping @autoclosure () throws -> String) -> Self {
        generate(key: \.nickname) { builder, _ in
            builder.set(\.$nickname, to: try nickname())
        }
    }
    
    func update(birthday: @escaping @autoclosure () throws -> Date) -> Self {
        generate(key: \.birthday) { builder, _ in
            builder.set(\.$birthday, to: try birthday())
        }
    }
    
    func update(other: @escaping @autoclosure () throws -> String?) -> Self {
        generate(key: \.other) { builder, _ in
            builder.set(\.$other, to: try other())
        }
    }
}

public extension PUserInfo.Updater {
    func update(identifier: @escaping (QUserInfo) throws -> String) -> Self {
        generate(needsPeek: true, key: \.identifier) { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$identifier, to: try identifier(q))
        }
    }
    
    func update(nickname: @escaping (QUserInfo) throws -> String) -> Self {
        generate(needsPeek: true, key: \.nickname) { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$nickname, to: try nickname(q))
        }
    }
    
    func update(birthday: @escaping (QUserInfo) throws -> Date) -> Self {
        generate(needsPeek: true, key: \.birthday) { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$birthday, to: try birthday(q))
        }
    }
    
    func update(other: @escaping (QUserInfo) throws -> String?) -> Self {
        generate(needsPeek: true, key: \.other) { builder, query in
            guard let q = query else { fatalError("应当提供 Query 结果，却没有提供") }
            return builder.set(\.$other, to: try other(q))
        }
    }
}

public extension QUserInfo {
    static func testMake(
        id: UUID,
        nickname: String,
        identifier: String,
        birthday: Date,
        other: String? = nil,
        user: TestingRelation<QUser, UUID>,
        alternateEmails: TestingRelation<[QInfoSlice<AlternateEmail>], Void> = .unset(()),
        phones: TestingRelation<[QInfoSlice<Phone>], Void> = .unset(()),
        addresses: TestingRelation<[QInfoSlice<Address>], Void> = .unset(()),
        createdAt: Date = .init(),
        updatedAt: Date = .init()
    ) -> Self {
        let userId = switch user {
        case .unset(let uuid): uuid
        case .set(let user): user.id
        }
        
        let info = QUserInfo(
            id: id,
            userId: userId,
            nickname: nickname,
            identifier: identifier,
            birthday: birthday,
            other: other,
            createdAt: createdAt,
            updatedAt: updatedAt,
            model: nil
        )
        
        info.$user.setIfNeed(to: user)
        info.$alternateEmails.setIfNeed(to: alternateEmails)
        info.$phones.setIfNeed(to: phones)
        info.$addresses.setIfNeed(to: addresses)
        
        return info
    }
}
