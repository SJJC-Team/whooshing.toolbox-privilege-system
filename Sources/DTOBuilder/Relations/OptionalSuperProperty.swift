import Foundation
import Query

public extension DTO.DBModel {
    typealias OptionalSuper<To> = OptionalSuperProperty<Self, To>
        where To: DTO.DBModel
}

// 需要隐式传递 id 值，即模型的 OptionalSuper 字段所存储的外键 id，非模型本体的 id 主键
// self.$<optional_super>.id == XXX
@propertyWrapper
final public class OptionalSuperProperty<From, To>: @unchecked Sendable
    where
        From: DTO.DBModel,
        To: DTO.DBModel
{
    public var projectedValue: OptionalSuperProperty<From, To> { self }
    
    public var wrappedValue: To? {
        lock.withLock {
            guard __loaded else {
                fatalError("\(Self.logName) 未加载，请调用 $ 前缀后调用 load(on:) 函数后再取得加载后的内容")
            }
            
            return __value
        }
    }
    
    public var id: UUID? {
        lock.withLock {
            guard __idGiven else {
                fatalError("模型的 OptionalSuper 字段所存储的外键 id 未赋值")
            }
            
            return __id
        }
    }
    
    package func set(id newValue: UUID?) {
        lock.withLock {
            __idGiven = true
            __id = newValue
        }
    }
    
    public var loaded: Bool {
        lock.withLock { __loaded }
    }
    
    private var __loaded: Bool = false
    private var __value: To? = nil
    private var __idGiven: Bool = false
    private var __id: UUID? = nil       // 是 OptionalSuper 字段所存储的外键 id，非模型本体的 id 主键
    private let lock = NIOLock()
    
    public init() {}
    
    public func inject(_ value: To?) {
        lock.withLock {
            __loaded = true
            __value = value
        }
    }
    
    public func get(on transactor: Transactor) -> EventLoopRes<To?, DTO.Errcase> {
        self.get(on: transactor.db)
    }
    
    public func load(on transactor: Transactor) -> EventLoopRes<Void, DTO.Errcase> {
        self.load(on: transactor.db)
    }
}
 
package extension OptionalSuperProperty {
    func get(on db: PGDatabase) -> EventLoopRes<To?, DTO.Errcase> {
        guard let id = self.id else {
            return db.eventLoop.makeSucceededResult(nil)
        }
        
        return To.query(on: db)
            .filter(\.id == id)
            .first()
            .errCast(DTO.Errcase.optionalSuperLoadFailed, "从数据库中查询 \(From.logName) 模型的 OptionalSuper \(To.logName) 模型失败", metadata: ["optional_super_id": .stringConvertible(id)], category: .internal)
            .flatMapThrowing
        { parent throws(DTO.Errcase.ErrType) in
            guard let p = parent else {
                throw DTO.Errcase.optionalSuperLoadFailed.d("数据库中 \(From.logName) 模型的 OptionalSuper \(To.logName) 不存在", category: .internal).metadata(["optional_super_id": .stringConvertible(id)])
            }
            
            self.lock.withLock {
                self.__loaded = true
                self.__value = p
            }
            
            return p
        }
    }
    
    func load(on db: PGDatabase) -> EventLoopRes<Void, DTO.Errcase> {
        get(on: db).map { _ in }
    }
}

extension OptionalSuperProperty: DTO.Property {
    // SuperProperty 需要存储外键 id，因此 hasId 为 true
    // 表示 contentId 将用于编码到 Encodable 中，参与 log 打印以及 json 的转换
    package static var hasId: Bool { true }
    // 需要确保 id 必须已从数据库加载，否则会导致崩溃，见 var id: UUID? 的定义
    package var contentId: UUID? { id }
    
    public static var logName: String { "OptionalSuper<\(From.logName), \(To.logName)>" }
    
    package var value: To? {
        lock.withLock { __value }
    }
}

extension OptionalSuperProperty: __Property {}

package extension OptionalSuperProperty {
    func setIfNeed(to value: TestingRelation<To?, UUID>) {
        if case let .set(v) = value {
            self.__loaded = true
            self.__value = v
        }
    }
}
