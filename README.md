# Whooshing 权限管理依赖库

本项目为 [Whooshing](https://github.com/whooshing-workshop/whooshing) 系统的**权限管理依赖库**，负责维护 **权限管理的数据结构**，并为 Whooshing 系统及其各服务模块提供全面的 **访问控制与权限管理** 功能。

它涵盖了 **权限授予、群组权限、用户权限、资源访问限制** 等多个层面，为系统提供灵活、高度可扩展的零信任权限及基于策略的自动化仲裁解决方案。

---

### 特性

- **灵活的权限定义**：权限以 [OPA (Open Policy Agent)](https://www.openpolicyagent.org/) 的 Rego 表达式形式定义与解析，支持复用与组合；也可使用类型安全的 Swift DSL（`BasicPolicy`）生成策略，无需手写 Rego。
- **严格的访问控制**：遵循最小权限原则，采用基于策略（Policy-based）的访问机制，利用 OPA 进行实时仲裁，确保安全边界清晰。
- **高度可定制**：允许通过 `@Resource` 宏自定义资源类型及其操作集合，从而实现极高颗粒度的精细化权限管理。
- **结构化权限体系**：支持用户、群组、域及群组内角色的权限层级定义，构建清晰的权限继承与隔离模型；提供角色保留名机制（如 `admin`）防止敏感角色被随意创建。
- **分布式架构设计**：采用分布式思路实现低耦合的模块交互。全局享有唯一的 `PrivilegeSystem` 处理账号、群组与全局策略，各个服务模块持有独立的 `PrivilegeModule` 处理本地资源。
- **类型安全的查询 DSL**：基于 Fluent 构建，直接以 DTO 的 KeyPath 进行过滤、排序、连接与聚合。
- **模块化实现**：以模块为单位组织功能，职责边界明确，便于扩展与维护。

---

### 结构设计

系统由核心系统控制器、子服务模块控制器以及 OPA 服务协同组成。

#### 模块业务及数据部署

全局统一认证系统分配全局角色及全局策略；业务模块挂载专属资源与相关权限。当仲裁请求发起时，合并各方策略由 OPA 进行终裁。

![11.模块分布式认证系统](diagrams/11.模块分布式认证系统.png)

#### OPA 模块同步

![12.OPA模块](diagrams/12.OPA模块.png)

#### 数据结构 - ERD

![15.SQL数据结构-ERD](diagrams/15.SQL数据结构-ERD.png)

要了解详细结构，请见[所有设计图](diagrams)

---

### 导入该依赖库

在你的 `Package.swift` 加入：

```swift
.package(url: "https://github.com/whooshing-workshop/whooshing.toolbox-privilege-system.git", from: "1.1.1")
```

本库提供以下产品，按需引入：

```swift
// 权限主系统：账号、用户资料、角色、群组、域、策略、仲裁器（含 PrivilegeModuleExtended）
.product(name: "PrivilegeSystem", package: "whooshing.toolbox-privilege-system"),
// 业务模块权限：模块私有资源与资源权限
.product(name: "PrivilegeModule", package: "whooshing.toolbox-privilege-system"),
// 主系统与业务模块共享的 DTO、认证数据与策略 DSL（PrivilegeModule 的超集）
.product(name: "PrivilegeModuleExtended", package: "whooshing.toolbox-privilege-system"),
// @Resource 宏
.product(name: "ResourceMacros", package: "whooshing.toolbox-privilege-system")
```

在需要的地方导入:

```swift
import PrivilegeSystem
import PrivilegeModule
```

> 本库使用了 Swift 6.3 的特性（宏与类型化抛错），编译时请确保工具链版本不低于 6.3。

---

### 使用介绍

#### 1. 系统与模块初始化

要进行权限管理，你需要分别启动 **全局系统** (`PrivilegeSystem`) 与 **业务模块** (`PrivilegeModule`)。通常这会在服务启动时进行。

```swift
import PrivilegeSystem
import PrivilegeModule

// 初始化全局权限系统 (负责用户、群组、全局角色等)
let system = try await PrivilegeSystem(
    eventLoop: eventLoop,
    dbConfigure: postgresConfigure,          // 数据库配置
    opaConfigure: .init(port: 8181),         // OPA 配置
    reservedRoleName: ["admin"],             // 角色保留名，不能通过 role.create 直接创建
    logger: .init(label: "PrivilegeSystem")
)

// 声明该模块下允许存在的资源类型集合
enum ResourceList: String, ResourceTypeList {
    case document
    case record
}

// 初始化您的业务服务权限模块 (负责此模块自有的资源与策略)
let module = try await PrivilegeModule<ResourceList>(
    moduleId: UUID(),                        // 您的模块唯一标识符
    eventLoop: eventLoop,
    dbConfigure: modulePostgresConfigure,
    opaConfigure: .init(port: 8181),
    logger: .init(label: "MyServiceModule")
)
```

> 若在 Whooshing 服务模块中使用，请通过 [whooshing.driver-privilege-system](https://github.com/whooshing-workshop/whooshing.driver-privilege-system) 提供的 `nexus.makePrivilegeSystem(...)` / `nexus.makePrivilegeModule(...)` 完成初始化，配置将自动从环境变量读取。

#### 2. 账号注册与鉴权准备

创建新用户并获取用户的 DTO：

```swift
let user = try await system.account.register(
    for: .init(
        email: "readme_user@example.com",
        hashedPassword: try Crypto.hash("SecurePassword123").get()
    )
)

// 登录后得到 QToken，其 credential 与 token 用于后续 API 的身份验证
let token = try await system.account.login(by: .init(email: "readme_user@example.com", hashedPassword: try Crypto.hash("SecurePassword123").get()))
```

#### 3. 定义并注册资源

业务模块独立管理其下的私有资源。使用 `@Resource` 宏声明资源类型，宏会自动生成 `json` 与 `mirrors`：

```swift
@Resource
struct DocumentResource {
    typealias ResourceType = ResourceList
    static let type: ResourceList = .document
    
    /// 业务层 ID，用于区分不同资源
    let appId: String
    let isPrivate: Bool
    
    /// 该资源支持的操作
    enum Operations: String, OperationList {
        case read
        case write
    }
}

// 资源落库，并取得数据库中的通用资源表示 GResource
let docResource = DocumentResource(appId: "Secret_Doc", isPrivate: true)
let resourceDTO = try await module.resource.create(resources: [docResource]).first!
let anyResourceDTO = GResource(resourceDTO)!
```

#### 4. 编写策略并挂载权限

策略可以直接书写 Rego，也可以使用 `BasicPolicy` DSL 生成：

```swift
// 方式一：手写 Rego（只需规则本体，package / import / default 由系统统一包装）
let myPolicy = """
allow if {
    input.operation == "read"
}
"""

// 方式二：Swift DSL，编译期校验字段路径与类型
let dslPolicy = PrivilegePolicy()
    .allow { $0.operation == "read" }
    .allow { $0.operation == "write" && $0.user.email.hasSuffix("@example.com") }
    .deny  { $0.resource.isPrivate == true && $0.role.name != "admin" }
    .policy

// 在模块内注册权限，并将其挂载至资源上
let privilegeDTO = try await module.privilege.createWithReturning(
    privileges: [PM.PPrivilege(name: "doc_reader", summary: "Read documents", policy: myPolicy)]
).first!

// 将权限和具体资源双向绑定 (attach)
try await module.privilege.attach {
    OrderedSet([privilegeDTO]) => OrderedSet([anyResourceDTO])
}
```

`BasicPolicy` 有三个特化类型，分别对应仲裁时 OPA 收到的三类 input：

| 特化类型 | 适用对象 | 独有字段 |
|---|---|---|
| `RolePolicy` | 角色策略 `PPolicy<Role>` | `roleId` |
| `DomainPolicy` | 域策略 `PPolicy<Domain>` | `domainId`、`group`（可为 null） |
| `PrivilegePolicy` | 资源权限 `PPrivilege` | `privilegeId` |

三者均可访问 `operation`、`user`、`role` 与 `resource`（动态 JSON，可用点语法任意下钻）。合成语义与 OPA 一致：同一 `allow` 内 `&&` 须全部满足，多个 `allow` 任一满足即可，任一 `deny` 命中即否决；未设置任何规则时拒绝所有。快捷入口有 `.allowAll` 与 `.denyAll`，DSL 未覆盖的表达式可用 `.raw("...")` 原样嵌入。

#### 5. 创建角色与人员指派

为用户分配职能（即“角色”）。角色本身也可以附加策略，作为请求资源时的基础门槛。

```swift
// 创建名为 "Document Viewer" 的角色
let role = try await system.role.create(
    roles: [.init(name: "Document Viewer", summary: "Can view docs")]
).first!

// 为角色分配额外的全局门槛策略 (可选)，策略按模块生效
let rolePolicyDTO = PPolicy<Role>(moduleId: module.moduleId, policy: RolePolicy.allowAll.policy)
let _ = try await system.policy.create(to: Role.self) {
    OrderedSet([rolePolicyDTO]) => role.id
}

// 指派角色到用户身上
try await system.role.appoint {
    OrderedSet([role]) => OrderedSet([user])
}
```

#### 6. 权限仲裁 (Arbitrator)

当用户发起请求时，使用仲裁器结合当前用户、其所用角色、请求的具体资源以及 OPA 策略，得出最终许可。

```swift
// 尝试对资源进行 `read` 操作
let readResult = try await system.arbitrator.judge(
    moduleId: module.moduleId,
    user: user,
    role: role,
    resource: anyResourceDTO,
    operation: .init(op: DocumentResource.Operations.read),
    privilegeIds: [privilegeDTO.id]
)

print(readResult.result)
// -> true (由于符合 "read" 操作要求，且角色验证通过)

// 尝试对该资源进行未许可的 `write` 操作
let writeResult = try await system.arbitrator.judge(
    moduleId: module.moduleId,
    user: user,
    role: role,
    resource: anyResourceDTO,
    operation: .init(op: DocumentResource.Operations.write),
    privilegeIds: [privilegeDTO.id]
)

print(writeResult.result)
// -> false (策略拦截)

// reports 保留每条策略的原始结果，便于排查为何被允许或拒绝
print(writeResult.reports)
```

> **提示:** 仲裁器会直接与 OPA 进行高性能通信，并将相关用户、角色、资源的元数据带入环境，无需您手动解析复杂的依赖网。`judge` 也提供仅传入 `userId` / `roleId` 的重载，便于服务间调用。

#### 7. 类型安全的查询 (Query DSL)

本库提供了一套基于 Fluent 构建的高级类型安全查询 DSL。它允许你直接使用 DTO 的 KeyPath 进行数据过滤、排序和连接，而无需直接接触底层的数据库模型。此外，系统针对各类聚合查询 (如 `sum`, `average`) 也提供了完善的封装映射。

```swift
// 通过系统的事务器查询用户，支持安全类型推断
let users = try await system.origin.query(QUser.self)
    .filter(\.email == "readme_user@example.com")
    .sort(\.createdAt, .descending)
    .limit(10)
    .all()

// 支持 Join 查询，并对 Join 表进行过滤与排序
let joined = try await system.origin.query(QUser.self)
    .join(QUserInfo.self, on: \QUser.id == \QUserInfo.$user.id)
    .sort(QUserInfo.self, \.nickname, .ascending)
    .all()
```

---

### 高阶特性

#### 丰富的时间和请求上下文验证

你可以通过 Rego 策略内置的方法利用 PostgreSQL 内的时间戳，执行复杂的过期失效、时区限制、特定时段判定。这同样无需调整业务代码，只需更新 OPA 策略本身。

```rego
allow if {
    r := pg.full_profile(input.user)
    
    # 限制只有在账户创建的当月能查看该私密文件
    date_arr := time.date(r.created_at.raw)
    date_arr[0] > 2025
}
```

DSL 同样支持日期字段的比较与拆解：

```swift
RolePolicy()
    .allow { $0.user.createdAt >= cutoffDate }         // input.user.created_at.raw >= ...
    .deny  { $0.user.createdAt.weekday == "Sunday" }
    .allow { _ in .raw(#"pg.profile(input.user).level >= 3"#) }   // 逃生舱口
```

#### 测试辅助

所有 DTO 类型均提供 `testMake(...)` 工厂方法，可在不接触数据库的情况下直接构造实例（如 `QUser.testMake(...)`、`QRole.testMake(...)`、`QToken.testMake(...)`），便于编写单元测试或调试白名单。**请勿在生产环境使用**。

如需了解更多模块化控制器的方法（例如群组 `Group`、域 `Domain`、用户资料 `UserInfo`），请参阅各模块内的源码注释。

---

### 运行环境

* **macOS** (> 11.0)
* **iOS** (> 14.0)
* **Linux** (> 20)
* **Swift** (> 6.3)
* **watchOS** (> 6.0) **[未测试]**
* **tvOS** (> 13) **[未测试]**

---

### 注意事项

- 本库依赖运行中的 **PostgreSQL** 与 **OPA / EOPA** 服务；单元测试会在检测到两者监听后才启用（`TestingShared.dbListening && TestingShared.opaListening`）。
- 同一 `(moduleId, 角色/域)` 下的策略在 OPA 中共用同一路径，请避免为同一角色在同一模块重复创建多条策略。
- 角色名命中 `reservedRoleName` 时 `role.create` 会被拒绝，请使用 `createAdminIfNotExist` 等专用方法创建。

---

### 联系与反馈

如有使用问题或建议，请通过 [GitHub Issues](https://github.com/whooshing-workshop/whooshing.toolbox-privilege-system/issues) 提交反馈。

或发至邮箱 [contact@official.whooshings.space](mailto:contact@official.whooshings.space)
