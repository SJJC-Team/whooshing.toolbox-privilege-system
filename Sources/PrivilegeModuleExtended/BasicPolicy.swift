import Vapor
import PrivilegeModule

// ============================================================================
// MARK: - BasicPolicy
// ============================================================================

/// 以类型安全的 Swift DSL 生成 OPA (Rego v1) 策略。
///
/// 使用体验对标 Vapor Fluent 的 `.filter`：`allow` / `deny` 的闭包参数
/// 是权限仲裁时 OPA `input` 的类型化镜像，字段路径、字段类型、日期编码
/// (`DateWrapper`) 均在编译期对齐，无需手写 rego 字符串。
///
/// ```swift
/// let policy = RolePolicy()
///     .allow { $0.operation == "read" }
///     .allow {
///         $0.operation == "write" &&
///         $0.user.email.hasSuffix("@bethelrc.org")
///     }
///     .deny { $0.resource.locked == true }
///
/// policy.policy   // 生成 rego 规则本体，交由 assemblePolicy 包装
/// ```
///
/// # 策略类型
///
/// 权限仲裁按权限类型传入不同的 input，三个特化类型与之一一对应，
/// 各自的字段镜像见对应的 `PolicyInput` 实现：
///
/// | 特化类型 | 仲裁 input | 独有字段 |
/// |---|---|---|
/// | ``RolePolicy`` | `RoleData` | `roleId` |
/// | ``DomainPolicy`` | `DomainData` | `domainId`、`group`（可为 null） |
/// | ``PrivilegePolicy`` | `PrivilegeData` | `privilegeId` |
///
/// 三者均包含 `operation`（本次操作）、`user`（发起用户）与
/// `resource`（资源 JSON，形状不固定）。
///
/// # 合成语义
///
/// 与 OPA 规则求值语义一致：
///
/// - 同一条规则内 `&&` 连接的条件须**全部满足**（同一 rule body）；
/// - 多次 `.allow` 或条件中的 `||` 为**任一满足**（展开为多个 rule body）；
/// - 任一 `.deny` 命中即**一票否决**，优先级高于所有 allow；
/// - 未设置任何规则时**拒绝所有**，与外层 `default allow := false` 一致；
/// - 条件引用的字段在 input 中缺失时，该条件**不成立**（rego undefined 语义）。
///
/// 快捷入口：``allowAll``（允许所有）、``denyAll``（拒绝所有，等价于空策略）。
///
/// # 条件运算符
///
/// 所有字段支持 `==` `!=`，可比较字段（数值、字符串、日期）另支持
/// `<` `<=` `>` `>=`。集合与字符串匹配：
///
/// ```swift
/// $0.operation.oneOf(["read", "list"])     // 值在集合内（Fluent 的 ~~）
/// $0.operation.notOneOf(["delete"])        // 值不在集合内
/// $0.user.email.hasPrefix("chenlin")       // startswith
/// $0.user.email.hasSuffix("@bethelrc.org") // endswith
/// $0.user.email.contains("@bethelrc")      // 子串包含
/// ```
///
/// 条件之间以 `&&` `||` `!` 自由组合、任意嵌套。生成时自动规范化为
/// 析取范式：`||` 展开为多个 rule body，`!` 经 De Morgan 律下推至叶子
/// 条件取反，因此任意组合均能生成合法的 Rego v1。
///
/// ```swift
/// .allow {
///     ($0.operation == "read" || $0.operation == "list") &&
///     !($0.resource.archived == true && $0.resource.owner != "system")
/// }
/// ```
///
/// # 日期字段
///
/// 仲裁 input 中的日期以 `DateWrapper` 对象编码。``DatePolicyField``
/// 与 `Date` 直接比较时自动落在 `.raw`（纳秒级 Unix 时间戳）上，
/// 亦可显式取 `year` / `month` / `day` / `hour` / `minute` / `second` /
/// `weekday`（英文全称，如 `"Monday"`）/ `iso8601` 子字段：
///
/// ```swift
/// .allow { $0.user.createdAt >= cutoffDate }        // input.user.created_at.raw >= ...
/// .deny  { $0.user.createdAt.weekday == "Sunday" }
/// .deny  { $0.user.createdAt.hour < 8 }
/// ```
///
/// # 动态资源字段
///
/// `resource` 为 ``JSONPolicyField``，点语法可任意下钻；非法标识符
/// 或与 rego 关键字冲突的 key 使用下标形式，生成时自动转为
/// `["..."]` 访问：
///
/// ```swift
/// .allow { $0.resource.meta.level >= 3 }
/// .allow { $0.resource["复杂 key"].exists }        // 存在且非 null
/// .allow { $0.resource.tags.includes("vip") }      // "vip" in input.resource.tags
/// ```
///
/// # 逃生舱口
///
/// DSL 未覆盖的表达式（如调用 rego utils 中的 pg 函数）以
/// ``PolicyPredicate/raw(_:)`` 原样嵌入，可与其他条件正常组合、取反：
///
/// ```swift
/// .allow { _ in .raw(#"pg.profile(input.user).level >= 3"#) }
/// ```
///
/// # 输出与接入
///
/// ``policy`` 生成的字符串只包含规则本体（若干 `allow if { ... }`，
/// 存在 deny 规则时会额外合成 `basic_allow` / `basic_deny` 中间规则），
/// `package` / `import` / `default allow := false` 由策略控制器的
/// `assemblePolicy` 统一包装。因此可直接作为 `PPolicy` / `PPrivilege`
/// 的 `policy` 字段入库：
///
/// ```swift
/// let pp = PPolicy<Role>(moduleId: moduleId, policy: policy.policy)
/// ```
///
/// 例如本文档开头的策略将生成：
///
/// ```rego
/// allow if {
///     basic_allow
///     not basic_deny
/// }
///
/// default basic_allow := false
///
/// basic_allow if {
///     input.operation == "read"
/// }
///
/// basic_allow if {
///     input.operation == "write"
///     endswith(input.user.email, "@bethelrc.org")
/// }
///
/// default basic_deny := false
///
/// basic_deny if {
///     input.resource.locked == true
/// }
/// ```
///
/// 类型本身遵循 `Codable` / `Hashable` / `Loggerable`，策略定义可
/// 序列化存储、参与日志 metadata 或在测试中做相等性断言。
///
/// - Important: 字段路径与仲裁模块的实际编码严格对齐——input 顶层键为
///   camelCase（`roleId` / `domainId` / `privilegeId`），`QUser` / `QGroup`
///   内部键为 snake_case（`created_at` 等），修改 DTO 编码时须同步更新
///   对应的 `PolicyInput` 镜像。
/// - Note: `||` 的析取范式展开在分支很多时会使规则数成倍增长，
///   基本策略通常无感；确有大量分支时建议拆分为多条 `.allow`。
public struct BasicPolicy<Input: PolicyInput>: Codable, Sendable, Hashable, CustomStringConvertible, Loggerable {

    /// 允许规则，彼此之间为「或」。
    public private(set) var allowRules: [PolicyPredicate]
    /// 否决规则，任一命中即拒绝。
    public private(set) var denyRules: [PolicyPredicate]

    /// 创建一个空策略（拒绝所有访问）。
    public init() {
        self.allowRules = []
        self.denyRules = []
    }

    /// 允许所有访问。
    public static var allowAll: Self { Self().allow { _ in .always } }

    /// 拒绝所有访问（等价于不设置任何规则）。
    public static var denyAll: Self { Self() }

    /// 追加一条允许规则。多条允许规则之间为「或」。
    ///
    /// ```swift
    /// DomainPolicy().allow { $0.group.name == "运营组" && $0.operation == "read" }
    /// ```
    public func allow(_ condition: (Input) -> PolicyPredicate) -> Self {
        var copy = self
        copy.allowRules.append(condition(Input()))
        return copy
    }

    /// 追加一条否决规则。任一命中即拒绝，优先级高于所有允许规则。
    ///
    /// ```swift
    /// PrivilegePolicy.allowAll.deny { $0.operation == "delete" }
    /// ```
    public func deny(_ condition: (Input) -> PolicyPredicate) -> Self {
        var copy = self
        copy.denyRules.append(condition(Input()))
        return copy
    }

    /// 生成最终的 rego 策略字符串。
    public var policy: String {
        let allows = allowRules.flatMap(\.dnfBranches).uniquedBranches()
        let denys = denyRules.flatMap(\.dnfBranches).uniquedBranches()

        // 没有否决规则时，直接展开为若干 allow 规则，保持输出最简
        guard !denys.isEmpty else {
            guard !allows.isEmpty else { return "allow if { false }" }
            return Self.render(rules: "allow", branches: allows).joined(separator: "\n\n")
        }

        // 存在否决规则时，通过中间规则合成「允许且未被否决」
        var parts: [String] = [
            """
            allow if {
                basic_allow
                not basic_deny
            }
            """,
            "default basic_allow := \(allows.isEmpty)"
        ]
        parts += Self.render(rules: "basic_allow", branches: allows)
        parts.append("default basic_deny := false")
        parts += Self.render(rules: "basic_deny", branches: denys)
        return parts.joined(separator: "\n\n")
    }

    public var description: String { self.policy }

    private static func render(rules head: String, branches: [[PolicyCondition]]) -> [String] {
        branches.map { branch in
            let conditions: [PolicyCondition] = branch.isEmpty ? [.always] : branch
            let body = conditions.map { "    " + $0.rego }.joined(separator: "\n")
            return "\(head) if {\n\(body)\n}"
        }
    }

    private enum CodingKeys: String, CodingKey {
        case allowRules = "allow_rules"
        case denyRules = "deny_rules"
    }
}

// ============================================================================
// MARK: - 条件与谓词
// ============================================================================

/// 一条原子条件，对应 rego rule body 中的一个表达式。
public struct PolicyCondition: Codable, Sendable, Hashable {

    public enum Operator: String, Codable, Sendable, Hashable {
        case equal, notEqual
        case less, lessOrEqual, greater, greaterOrEqual
        case contains, notContains
        case startsWith, notStartsWith
        case endsWith, notEndsWith
        case oneOf, notOneOf
        case raw, notRaw
    }

    /// 左值（rego 路径，`raw` 时为完整表达式）。
    public let lhs: String
    public let op: Operator
    /// 右值（已渲染的 rego 字面量，`raw` 时为空）。
    public let rhs: String

    public init(lhs: String, op: Operator, rhs: String) {
        self.lhs = lhs
        self.op = op
        self.rhs = rhs
    }

    static let always = PolicyCondition(lhs: "true", op: .raw, rhs: "")

    /// 逻辑取反（用于将 `!` 下推到叶子条件）。
    var negated: PolicyCondition {
        let flipped: Operator = switch op {
        case .equal: .notEqual
        case .notEqual: .equal
        case .less: .greaterOrEqual
        case .greaterOrEqual: .less
        case .greater: .lessOrEqual
        case .lessOrEqual: .greater
        case .contains: .notContains
        case .notContains: .contains
        case .startsWith: .notStartsWith
        case .notStartsWith: .startsWith
        case .endsWith: .notEndsWith
        case .notEndsWith: .endsWith
        case .oneOf: .notOneOf
        case .notOneOf: .oneOf
        case .raw: .notRaw
        case .notRaw: .raw
        }
        return .init(lhs: lhs, op: flipped, rhs: rhs)
    }

    /// 渲染为 rego 表达式。
    var rego: String {
        switch op {
        case .equal: "\(lhs) == \(rhs)"
        case .notEqual: "\(lhs) != \(rhs)"
        case .less: "\(lhs) < \(rhs)"
        case .lessOrEqual: "\(lhs) <= \(rhs)"
        case .greater: "\(lhs) > \(rhs)"
        case .greaterOrEqual: "\(lhs) >= \(rhs)"
        case .contains: "contains(\(lhs), \(rhs))"
        case .notContains: "not contains(\(lhs), \(rhs))"
        case .startsWith: "startswith(\(lhs), \(rhs))"
        case .notStartsWith: "not startswith(\(lhs), \(rhs))"
        case .endsWith: "endswith(\(lhs), \(rhs))"
        case .notEndsWith: "not endswith(\(lhs), \(rhs))"
        case .oneOf: "\(lhs) in \(rhs)"
        case .notOneOf: "not \(lhs) in \(rhs)"
        case .raw: lhs
        case .notRaw: "not \(lhs)"
        }
    }
}

/// 条件组合树。支持 `&&`、`||`、`!` 自由组合，
/// 生成策略时会自动规范化为析取范式（多个 rule body 的「或」）。
public indirect enum PolicyPredicate: Codable, Sendable, Hashable {
    case condition(PolicyCondition)
    case and([PolicyPredicate])
    case or([PolicyPredicate])
    case not(PolicyPredicate)

    /// 恒真条件。
    public static var always: PolicyPredicate { .condition(.always) }

    /// 恒假条件。
    public static var never: PolicyPredicate { .not(.always) }

    /// 逃生舱口：原样嵌入一段 rego 表达式（单条表达式）。
    ///
    /// ```swift
    /// .allow { _ in .raw(#"pg.profile(input.user).level >= 3"#) }
    /// ```
    public static func raw(_ expression: String) -> PolicyPredicate {
        .condition(.init(lhs: expression, op: .raw, rhs: ""))
    }

    /// 析取范式：外层数组为「或」，内层数组为「且」。
    var dnfBranches: [[PolicyCondition]] {
        switch self {
        case .condition(let c):
            return [[c]]
        case .or(let ps):
            return ps.flatMap(\.dnfBranches)
        case .and(let ps):
            return ps.reduce([[]]) { acc, p in
                let branches = p.dnfBranches
                return acc.flatMap { done in branches.map { done + $0 } }
            }
        case .not(let p):
            return p.negatedDNF
        }
    }

    /// `not self` 的析取范式（De Morgan 展开，取反下推到叶子）。
    private var negatedDNF: [[PolicyCondition]] {
        switch self {
        case .condition(let c): [[c.negated]]
        case .not(let p): p.dnfBranches
        case .and(let ps): PolicyPredicate.or(ps.map { .not($0) }).dnfBranches
        case .or(let ps): PolicyPredicate.and(ps.map { .not($0) }).dnfBranches
        }
    }
}

public func && (lhs: PolicyPredicate, rhs: PolicyPredicate) -> PolicyPredicate {
    .and([lhs, rhs])
}

public func || (lhs: PolicyPredicate, rhs: PolicyPredicate) -> PolicyPredicate {
    .or([lhs, rhs])
}

public prefix func ! (predicate: PolicyPredicate) -> PolicyPredicate {
    .not(predicate)
}

// ============================================================================
// MARK: - 字面量
// ============================================================================

/// 可以渲染为 rego 字面量的值。
public protocol PolicyValue: Sendable {
    /// 该值在 rego 中的字面量表示。
    var opaLiteral: String { get }
}

/// 支持 `<` `<=` `>` `>=` 比较的值。
public protocol ComparablePolicyValue: PolicyValue {}

extension String: PolicyValue, ComparablePolicyValue {
    public var opaLiteral: String { self.opaStringLiteral }
}

extension Bool: PolicyValue {
    public var opaLiteral: String { self ? "true" : "false" }
}

extension UUID: PolicyValue {
    /// 与 `JSONEncoder` 对 UUID 的编码一致（大写 uuidString）。
    public var opaLiteral: String { "\"\(self.uuidString)\"" }
}

extension Date: PolicyValue, ComparablePolicyValue {
    /// 与 `DateWrapper.raw` 对齐：纳秒级 Unix 时间戳。
    public var opaLiteral: String {
        String(Int64(self.timeIntervalSince1970 * 1_000_000_000))
    }
}

extension Int: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }
extension Int8: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }
extension Int16: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }
extension Int32: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }
extension Int64: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }
extension UInt: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }
extension UInt8: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }
extension UInt16: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }
extension UInt32: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }
extension UInt64: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }
extension Double: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }
extension Float: PolicyValue, ComparablePolicyValue { public var opaLiteral: String { String(self) } }

extension Optional: PolicyValue where Wrapped: PolicyValue {
    public var opaLiteral: String {
        switch self {
        case .none: "null"
        case .some(let value): value.opaLiteral
        }
    }
}

extension Array: PolicyValue where Element: PolicyValue {
    public var opaLiteral: String {
        "[" + self.map(\.opaLiteral).joined(separator: ", ") + "]"
    }
}

// ============================================================================
// MARK: - 字段
// ============================================================================

/// input 中的一个类型化字段。`Value` 仅作编译期约束，保证比较值类型正确。
public struct PolicyField<Value: PolicyValue>: Sendable {
    /// 完整 rego 路径，例如 `input.user.email`。
    public let path: String

    public init(_ path: String) {
        self.path = path
    }

    /// 字段值在给定集合内（Fluent 的 `~~`）。
    public func oneOf(_ values: [Value]) -> PolicyPredicate {
        .condition(.init(lhs: path, op: .oneOf, rhs: values.opaLiteral))
    }

    /// 字段值不在给定集合内。
    public func notOneOf(_ values: [Value]) -> PolicyPredicate {
        .condition(.init(lhs: path, op: .notOneOf, rhs: values.opaLiteral))
    }
}

public extension PolicyField where Value == String {
    /// 字符串包含子串。
    func contains(_ substring: String) -> PolicyPredicate {
        .condition(.init(lhs: path, op: .contains, rhs: substring.opaLiteral))
    }

    /// 字符串前缀匹配。
    func hasPrefix(_ prefix: String) -> PolicyPredicate {
        .condition(.init(lhs: path, op: .startsWith, rhs: prefix.opaLiteral))
    }

    /// 字符串后缀匹配。
    func hasSuffix(_ suffix: String) -> PolicyPredicate {
        .condition(.init(lhs: path, op: .endsWith, rhs: suffix.opaLiteral))
    }
}

public func == <V: PolicyValue>(lhs: PolicyField<V>, rhs: V) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .equal, rhs: rhs.opaLiteral))
}

public func != <V: PolicyValue>(lhs: PolicyField<V>, rhs: V) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .notEqual, rhs: rhs.opaLiteral))
}

public func < <V: ComparablePolicyValue>(lhs: PolicyField<V>, rhs: V) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .less, rhs: rhs.opaLiteral))
}

public func <= <V: ComparablePolicyValue>(lhs: PolicyField<V>, rhs: V) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .lessOrEqual, rhs: rhs.opaLiteral))
}

public func > <V: ComparablePolicyValue>(lhs: PolicyField<V>, rhs: V) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .greater, rhs: rhs.opaLiteral))
}

public func >= <V: ComparablePolicyValue>(lhs: PolicyField<V>, rhs: V) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .greaterOrEqual, rhs: rhs.opaLiteral))
}

/// 日期字段。仲裁 input 中的日期以 `DateWrapper` 对象编码，
/// 与 `Date` 直接比较时自动落在 `.raw`（纳秒时间戳）上。
///
/// ```swift
/// $0.user.createdAt < someDate        // input.user.created_at.raw < 1757...
/// $0.user.createdAt.weekday == "Monday"
/// $0.user.createdAt.hour < 18
/// ```
public struct DatePolicyField: Sendable {
    public let path: String

    public init(_ path: String) {
        self.path = path
    }

    /// 纳秒级 Unix 时间戳。
    public var raw: PolicyField<Int64> { .init(path + ".raw") }
    public var year: PolicyField<Int> { .init(path + ".year") }
    public var month: PolicyField<Int> { .init(path + ".month") }
    public var day: PolicyField<Int> { .init(path + ".day") }
    public var hour: PolicyField<Int> { .init(path + ".hour") }
    public var minute: PolicyField<Int> { .init(path + ".minute") }
    public var second: PolicyField<Int> { .init(path + ".second") }
    /// 英文星期全称，例如 `"Monday"`。
    public var weekday: PolicyField<String> { .init(path + ".weekday") }
    public var iso8601: PolicyField<String> { .init(path + ".iso8601") }
}

public func == (lhs: DatePolicyField, rhs: Date) -> PolicyPredicate { lhs.raw == Int64(from: rhs) }
public func != (lhs: DatePolicyField, rhs: Date) -> PolicyPredicate { lhs.raw != Int64(from: rhs) }
public func < (lhs: DatePolicyField, rhs: Date) -> PolicyPredicate { lhs.raw < Int64(from: rhs) }
public func <= (lhs: DatePolicyField, rhs: Date) -> PolicyPredicate { lhs.raw <= Int64(from: rhs) }
public func > (lhs: DatePolicyField, rhs: Date) -> PolicyPredicate { lhs.raw > Int64(from: rhs) }
public func >= (lhs: DatePolicyField, rhs: Date) -> PolicyPredicate { lhs.raw >= Int64(from: rhs) }

private extension Int64 {
    init(from date: Date) {
        self = Int64(date.timeIntervalSince1970 * 1_000_000_000)
    }
}

/// 动态 JSON 字段（用于 `input.resource` 这类形状不固定的数据）。
/// 支持点语法与下标任意深入，可直接与字面量比较。
///
/// ```swift
/// $0.resource.global == true
/// $0.resource.meta.level >= 3
/// $0.resource["复杂 key"].exists
/// $0.resource.tags.includes("vip")
/// ```
@dynamicMemberLookup
public struct JSONPolicyField: Sendable {
    public let path: String

    public init(_ path: String) {
        self.path = path
    }

    public subscript(dynamicMember key: String) -> JSONPolicyField {
        self[key]
    }

    public subscript(_ key: String) -> JSONPolicyField {
        key.isRegoIdentifier
        ? .init(path + "." + key)
        : .init(path + "[\(key.opaStringLiteral)]")
    }

    /// 字段存在且非 null。
    public var exists: PolicyPredicate {
        .condition(.init(lhs: path, op: .notEqual, rhs: "null"))
    }

    /// 字段为 null（注意：字段完全缺失时该条件不成立）。
    public var isNull: PolicyPredicate {
        .condition(.init(lhs: path, op: .equal, rhs: "null"))
    }

    /// 字符串字段包含子串。
    public func contains(_ substring: String) -> PolicyPredicate {
        .condition(.init(lhs: path, op: .contains, rhs: substring.opaLiteral))
    }

    /// 字符串字段前缀匹配。
    public func hasPrefix(_ prefix: String) -> PolicyPredicate {
        .condition(.init(lhs: path, op: .startsWith, rhs: prefix.opaLiteral))
    }

    /// 字符串字段后缀匹配。
    public func hasSuffix(_ suffix: String) -> PolicyPredicate {
        .condition(.init(lhs: path, op: .endsWith, rhs: suffix.opaLiteral))
    }

    /// 数组字段包含给定元素。
    public func includes(_ element: some PolicyValue) -> PolicyPredicate {
        .condition(.init(lhs: element.opaLiteral, op: .oneOf, rhs: path))
    }

    /// 字段值在给定集合内。
    public func oneOf(_ values: [some PolicyValue]) -> PolicyPredicate {
        .condition(.init(lhs: path, op: .oneOf, rhs: values.opaLiteral))
    }

    /// 字段值不在给定集合内。
    public func notOneOf(_ values: [some PolicyValue]) -> PolicyPredicate {
        .condition(.init(lhs: path, op: .notOneOf, rhs: values.opaLiteral))
    }
}

public func == (lhs: JSONPolicyField, rhs: some PolicyValue) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .equal, rhs: rhs.opaLiteral))
}

public func != (lhs: JSONPolicyField, rhs: some PolicyValue) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .notEqual, rhs: rhs.opaLiteral))
}

public func < (lhs: JSONPolicyField, rhs: some ComparablePolicyValue) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .less, rhs: rhs.opaLiteral))
}

public func <= (lhs: JSONPolicyField, rhs: some ComparablePolicyValue) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .lessOrEqual, rhs: rhs.opaLiteral))
}

public func > (lhs: JSONPolicyField, rhs: some ComparablePolicyValue) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .greater, rhs: rhs.opaLiteral))
}

public func >= (lhs: JSONPolicyField, rhs: some ComparablePolicyValue) -> PolicyPredicate {
    .condition(.init(lhs: lhs.path, op: .greaterOrEqual, rhs: rhs.opaLiteral))
}

// ============================================================================
// MARK: - input 镜像
// ============================================================================

/// OPA `input` 的类型化镜像。
public protocol PolicyInput: Sendable {
    init()
}

/// 用户字段（`QUser` 编码后的形状）。
public struct UserPolicyFields: Sendable {
    public let path: String

    public init(_ path: String) {
        self.path = path
    }

    public var id: PolicyField<UUID> { .init(path + ".id") }
    public var email: PolicyField<String> { .init(path + ".email") }
    public var createdAt: DatePolicyField { .init(path + ".created_at") }
    public var updatedAt: DatePolicyField { .init(path + ".updated_at") }

    /// 逃生舱口：以动态 JSON 字段访问编码后的任意路径。
    public subscript(_ key: String) -> JSONPolicyField {
        JSONPolicyField(path)[key]
    }
}

/// 用户字段（`QRole` 编码后的形状）。
public struct RolePolicyFields: Sendable {
    public let path: String

    public init(_ path: String) {
        self.path = path
    }

    public var id: PolicyField<UUID> { .init(path + ".id") }
    public var name: PolicyField<String> { .init(path + ".name") }
    public var summary: PolicyField<String> { .init(path + ".summary") }
    public var createdAt: DatePolicyField { .init(path + ".created_at") }
    public var updatedAt: DatePolicyField { .init(path + ".updated_at") }

    /// 逃生舱口：以动态 JSON 字段访问编码后的任意路径。
    public subscript(_ key: String) -> JSONPolicyField {
        JSONPolicyField(path)[key]
    }
}


/// 群组字段（`QGroup` 编码后的形状）。
public struct GroupPolicyFields: Sendable {
    public let path: String

    public init(_ path: String) {
        self.path = path
    }

    public var id: PolicyField<UUID> { .init(path + ".id") }
    public var name: PolicyField<String> { .init(path + ".name") }
    public var summary: PolicyField<String> { .init(path + ".summary") }
    public var parentId: PolicyField<UUID> { .init(path + ".parent_id") }
    public var createdAt: DatePolicyField { .init(path + ".created_at") }
    public var updatedAt: DatePolicyField { .init(path + ".updated_at") }

    /// 群组存在（域权限经由群组授予；用户直接被授予时为 null）。
    public var exists: PolicyPredicate {
        .condition(.init(lhs: path, op: .notEqual, rhs: "null"))
    }

    /// 逃生舱口：以动态 JSON 字段访问编码后的任意路径。
    public subscript(_ key: String) -> JSONPolicyField {
        JSONPolicyField(path)[key]
    }
}

/// 角色策略的 input（对应仲裁请求中的 `RoleData`）。
public struct RolePolicyInput: PolicyInput {
    public let roleId = PolicyField<UUID>("input.roleId")
    public let operation = PolicyField<String>("input.operation")
    public let user = UserPolicyFields("input.user")
    public let role = RolePolicyFields("input.role")
    public let resource = JSONPolicyField("input.resource")

    public init() {}
}

/// 域策略的 input（对应仲裁请求中的 `DomainData`）。
public struct DomainPolicyInput: PolicyInput {
    public let domainId = PolicyField<UUID>("input.domainId")
    public let operation = PolicyField<String>("input.operation")
    public let user = UserPolicyFields("input.user")
    public let role = RolePolicyFields("input.role")
    /// 该域经由哪个群组授予；用户直接被授予时为 null。
    public let group = GroupPolicyFields("input.group")
    public let resource = JSONPolicyField("input.resource")

    public init() {}
}

/// 资源权限策略的 input（对应仲裁请求中的 `PrivilegeData`）。
public struct PrivilegePolicyInput: PolicyInput {
    public let privilegeId = PolicyField<UUID>("input.privilegeId")
    public let operation = PolicyField<String>("input.operation")
    public let user = UserPolicyFields("input.user")
    public let role = RolePolicyFields("input.role")
    public let resource = JSONPolicyField("input.resource")

    public init() {}
}

/// 角色策略。
public typealias RolePolicy = BasicPolicy<RolePolicyInput>
/// 域策略。
public typealias DomainPolicy = BasicPolicy<DomainPolicyInput>
/// 资源权限策略。
public typealias PrivilegePolicy = BasicPolicy<PrivilegePolicyInput>

// ============================================================================
// MARK: - 内部工具
// ============================================================================

extension String {
    /// 渲染为 rego 字符串字面量（JSON 转义）。
    var opaStringLiteral: String {
        var result = "\""
        for scalar in self.unicodeScalars {
            switch scalar {
            case "\"": result += "\\\""
            case "\\": result += "\\\\"
            case "\n": result += "\\n"
            case "\r": result += "\\r"
            case "\t": result += "\\t"
            default:
                if scalar.value < 0x20 {
                    result += String(format: "\\u%04x", scalar.value)
                } else {
                    result.unicodeScalars.append(scalar)
                }
            }
        }
        return result + "\""
    }

    private static let regoKeywords: Set<String> = [
        "as", "contains", "default", "else", "every", "false", "if", "import",
        "in", "not", "null", "package", "some", "true", "with"
    ]

    /// 是否可以作为 rego 点语法路径段（否则须使用 `["..."]` 下标形式）。
    var isRegoIdentifier: Bool {
        guard !self.isEmpty, !Self.regoKeywords.contains(self) else { return false }
        guard let first = self.unicodeScalars.first else { return false }

        func isLetterOrUnderscore(_ s: Unicode.Scalar) -> Bool {
            s == "_" || ("a"..."z").contains(s) || ("A"..."Z").contains(s)
        }
        func isDigit(_ s: Unicode.Scalar) -> Bool {
            ("0"..."9").contains(s)
        }

        guard isLetterOrUnderscore(first) else { return false }
        return self.unicodeScalars.dropFirst().allSatisfy { isLetterOrUnderscore($0) || isDigit($0) }
    }
}

private extension [[PolicyCondition]] {
    /// 去除分支内重复条件与完全重复的分支，保持顺序稳定。
    func uniquedBranches() -> [[PolicyCondition]] {
        var seenBranches = Set<[PolicyCondition]>()
        var result: [[PolicyCondition]] = []
        for branch in self {
            var seen = Set<PolicyCondition>()
            let deduped = branch.filter { seen.insert($0).inserted }
            if seenBranches.insert(deduped).inserted {
                result.append(deduped)
            }
        }
        return result
    }
}

public extension PrivilegeModule.PPrivilege {
    init(
        id: UUID? = nil,
        name: String? = nil,
        summary: String? = nil,
        policy: PrivilegePolicy
    ) {
        self = Self.init(
            id: id,
            name: name,
            summary: summary,
            policy: policy
        )
    }
    
    init(
        id: UUID? = nil,
        name: String? = nil,
        summary: String? = nil,
        policy: @Sendable @escaping (PrivilegePolicy) -> PrivilegePolicy
    ) {
        self = Self.init(
            id: id,
            name: name,
            summary: summary,
            policy: policy(.init()).policy
        )
    }
}
