import Foundation
import Query

public extension DTO.DBModel {
    typealias Super<To> = SuperProperty<Self, To>
        where To: DTO.DBModel
}

// 需要隐式传递 id 值，即模型的 Super 字段所存储的外键 id，非模型本体的 id 主键
// self.$<super>.id == XXX
@propertyWrapper
final public class SuperProperty<From, To>: @unchecked Sendable
    where
        From: DTO.DBModel,
        To: DTO.DBModel
{
    public var projectedValue: SuperProperty<From, To> { self }
    
    public var wrappedValue: To {
        lock.withLock {
            guard loaded else {
                fatalError("Super 未加载，请调用 $ 前缀后调用 load(on:) 函数后再取得加载后的内容")
            }
            
            return __value!
        }
    }

    public var id: UUID {
        lock.withLock {
            guard let id = __id else {
                fatalError("模型的 Super 字段所存储的外键 id 未赋值")
            }
            
            return id
        }
    }
    
    package func set(id newValue: UUID) {
        lock.withLock { __id = newValue }
    }
    
    public var loaded: Bool { __value != nil }
    
    package var __value: To? = nil
    package var __id: UUID? = nil   // 是 Super 字段所存储的外键 id，非模型本体的 id 主键
    private let lock = NIOLock()
    
    public init() {}
    
    public func inject(_ value: To) {
        lock.withLock {
            __value = value
        }
    }
    
    public func get(on transactor: Transactor) -> EventLoopRes<To, DTO.Errcase> {
        self.get(on: transactor.db)
    }
    
    public func load(on transactor: Transactor) -> EventLoopRes<Void, DTO.Errcase> {
        self.load(on: transactor.db)
    }
}
 
package extension SuperProperty {
    func get(on db: PGDatabase) -> EventLoopRes<To, DTO.Errcase> {
        To.query(on: db)
            .filter(\.id == id)
            .first()
            .errCast(DTO.Errcase.superLoadFailed, "从数据库中查询 \(From.logName) 模型的 Super \(To.logName) 模型失败", metadata: ["super_id": .stringConvertible(self.id)], category: .internal)
            .flatMapThrowing
        { Super throws(DTO.Errcase.ErrType) in
            guard let p = Super else {
                throw DTO.Errcase.superLoadFailed.d("数据库中 \(From.logName) 模型的 Super \(To.logName) 不存在", category: .internal).metadata(["super_id": .stringConvertible(self.id)])
            }
            
            self.lock.withLock {
                self.__value = p
            }
            
            return p
        }
    }
    
    func load(on db: PGDatabase) -> EventLoopRes<Void, DTO.Errcase> {
        get(on: db).map { _ in }
    }
}

extension SuperProperty: DTO.Property {
    // SuperProperty 需要存储外键 id，因此 hasId 为 true
    // 表示 contentId 将用于编码到 Encodable 中，参与 log 打印以及 json 的转换
    package static var hasId: Bool { true }
    // 需要确保 id 必须存在，因为其存在于数据库记录中，若此处 id 不存在会导致崩溃，见 var id: UUID 的定义
    package var contentId: UUID? { id }
    
    public static var logName: String { "Super<\(From.logName), \(To.logName)>" }
    
    package var value: To? {
        lock.withLock { __value }
    }
}

extension SuperProperty: __Property {}

package extension SuperProperty {
    func setIfNeed(to value: TestingRelation<To, UUID>) {
        if case let .set(v) = value {
            self.__value = v
        }
    }
}
