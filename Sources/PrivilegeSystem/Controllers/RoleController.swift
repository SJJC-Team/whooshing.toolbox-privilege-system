import Query
import Foundation
import PrivilegeModule
import NIOHTTP1

extension PrivilegeSystem {
    /// 角色控制器，提供对于角色（Role）的创建、更新、删除以及指派和查询功能。
    ///
    /// 角色（Role）在权限系统中代表一组权限或行为的抽象。它可以通过以下方式被指派：
    /// 1. 直接指派给用户（用户角色）。
    /// 2. 指派给群组，那么群组内所有成员默认继承该角色（群组角色）。
    /// 3. 在特定群组上下文下指派给某个用户，即该角色仅在用户身处该群组的语境时生效（组内角色）。
    ///
    /// - `create` / `delete` / `update`: 角色的生命周期管理。
    /// - `appoint` / `dismiss`: 进行角色的指派或撤销指派。支持多对多操作。
    /// - `roles` / `verify` / `is`: 动态查询和验证角色指派情况。
    public final class RoleController: SystemController {
        package let db: PGDatabase
        package let eventLoop: EventLoop
        package let reservedRoleName: [String]
        
        let policyController: PolicyController
        
        /// 操作记录日志器。
        public let logger: Logger
        
        init(
            db: PGDatabase,
            eventLoop: EventLoop,
            policyController: PolicyController,
            reservedRoleName: [String],
            logger: Logger
        ) {
            self.db = db
            self.eventLoop = eventLoop
            self.policyController = policyController
            self.reservedRoleName = reservedRoleName
            self.logger = logger
        }
        
        /// 批量创建角色并附带 OPA 策略。
        ///
        /// 允许在声明角色的同时将一条或多条 `DTO.Policy` 关联到该角色。底层通过事务保证原子性。
        ///
        /// - Parameter content: `MTORelationBuilder` 闭包，用于构建角色与策略间的多对一关系。
        /// - Returns: `EventLoopRes<Void, Errcase>`
        ///
        /// ```swift
        /// try await system.role.create {
        ///     [rolePolicyDTO] => roleDTO
        /// }.get()
        /// ```
        public func create(
            on transactor: Transactor? = nil,
            @MTORelationBuilder<PPolicy<Role>, PRole>
            _ content: @Sendable @escaping () ->OrderedSet<MTORelation<PPolicy<Role>, PRole>>
        ) -> EventLoopRes<Void, Errcase> {
            create(relations: content(), on: transactor)
        }
        
        /// 批量创建角色并附带 OPA 策略，返回存入的策略查询结构。
        ///
        /// - Parameter content: `MTORelationBuilder` 闭包，用于构建角色与策略间的多对一关系。
        /// - Returns: 一个字典，Key为角色的 ID，Value 为该角色关联的策略查询对象 `QPolicy<Role>`。
        public func createWithReturning(
            on transactor: Transactor? = nil,
            @MTORelationBuilder<PPolicy<Role>, PRole>
            _ content: @Sendable @escaping () ->OrderedSet<MTORelation<PPolicy<Role>, PRole>>
        ) -> EventLoopRes<[UUID: [QPolicy<Role>]], Errcase> {
            createWithReturning(relations: content(), on: transactor)
        }
        
        /// 批量创建裸角色（无策略附带）。
        ///
        /// - Parameter roles: 一组准备落库的角色对象。
        /// - Returns: 成功后返回携带数据库 UUID 的查询对象 `QRole` 数组。
        ///
        /// ```swift
        /// let roles = try await system.role.create(
        ///     roles: [.init(name: "Admin", summary: "Administrator Role")]
        /// ).get()
        /// ```
        public func create(
            roles:OrderedSet<PRole>,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<[QRole], Errcase> {
            let logger = getActionLogger()
            logger.info("执行 创建角色 操作", metadata: ["roles": .summaryData(roles)])
            logger.debug("操作参数", metadata: ["roles": .data(roles)])
            let db = transactor?.db ?? self.db
            return __create(on: db, roles: roles, noReservedName: false).map {
                logger.info("创建角色 操作成功", metadata: ["data": .summaryData($0)])
                logger.debug("创建角色 结果详细数据", metadata: ["data": .data($0)])
                return $0 
            }.logIfFail(logger: logger)
        }
        
        /// 根据 ID 批量删除角色。
        ///
        /// - Parameters:
        ///   - roleIds: 欲删除角色的 UUID 数组。
        /// - Returns: `EventLoopRes<Void, Errcase>`
        public func delete(
            roleIds: OrderedSet<UUID>,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<Void, Errcase> {
            let logger = getActionLogger()
            logger.info("执行 删除角色 操作", metadata: ["roleIds": .summaryData(roleIds)])
            logger.debug("操作参数", metadata: ["roleIds": .data(roleIds)])
            let db = transactor?.db ?? self.db
            return __delete(
                on: db,
                QRole.self,
                ids: roleIds,
                label: "角色",
                errThrowing: .roleDeleteFailed,
                fieldBuilder: { $0.field(\.$id) },
                filterBuilder: { $0.filter(\.$id ~~ roleIds) }
            )
            .map { logger.info("删除角色 操作成功") }
            .logIfFail(logger: logger)
        }
        
        /// 更新指定角色的元信息。
        ///
        /// - Parameter updater: 更新器对象 `PRole.Updater`。
        /// - Returns: 更新完毕的角色对象 `QRole`。
        public func update(
            with updater: PRole.Updater,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<QRole, Errcase> {
            let logger = getActionLogger()
            logger.info("执行 更新角色 操作", metadata: ["data": .summaryData(updater)])
            logger.debug("更新角色 详细请求数据", metadata: ["data": .data(updater)])
            let db = transactor?.db ?? self.db
            let roleId = updater.roleId
            updater.reservedRoleNames = self.reservedRoleName
            return __update(
                on: db,
                updater: updater,
                label: "角色",
                errThrowing: .roleUpdateFailed,
                filterBuilder: { $0.filter(\.$id == roleId) },
                dtoBuilder: { QRole.make(from: $0) }
            )
            .map { 
                logger.info("更新角色 操作成功", metadata: ["data": .summaryData($0)])
                logger.debug("更新角色 结果详细数据", metadata: ["data": .data($0)])
                return $0 
            }
            .logIfFail(logger: logger)
        }
    }
}

public extension PrivilegeSystem.RoleController {
    func create(
        relations:OrderedSet<MTORelation<PPolicy<Role>, PRole>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 创建角色（含策略） 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("操作参数", metadata: ["relations": .data(relations)])
        
        let db = transactor?.db ?? self.db
        
        return db.trans(throws: .roleCreateFailed, "数据库事务执行失败", category: .internal) { db in
            self.__create(on: db, roles: relations.mapToSet { $0.right }, noReservedName: false).flatMap { roles in
                self.policyController.__create(
                    on: db,
                    to: Role.self,
                    relations: relations.enumeratedSet().mapToSet { .init(left: $0.element.left, right: roles[$0.offset].id) }
                )
            }
        }.map { logger.info("创建角色（含策略） 操作成功") }
        .logIfFail(logger: logger)
    }
    
    func createWithReturning(
        relations:OrderedSet<MTORelation<PPolicy<Role>, PRole>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[UUID: [QPolicy<Role>]], PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 创建角色（含策略返回） 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("操作参数", metadata: ["relations": .data(relations)])
        
        let db = transactor?.db ?? self.db
        
        return db.trans(throws: .roleCreateFailed, "数据库事务执行失败", category: .internal) { db in
            self.__create(on: db, roles: relations.mapToSet { $0.right }, noReservedName: false).flatMap { roles in
                self.policyController.__createWithReturning(
                    on: db,
                    to: Role.self,
                    relations: relations.enumeratedSet().mapToSet { .init(left: $0.element.left, right: roles[$0.offset].id) }
                )
            }
        }.map {
            logger.info("创建角色（含策略返回） 操作成功", metadata: ["data": .summaryData($0)])
            logger.debug("创建角色（含策略返回） 结果详细数据", metadata: ["data": .data($0)])
            return $0
        }.logIfFail(logger: logger)
    }
}

public extension PrivilegeSystem.RoleController {
    // MARK: - 角色任命
    
    func appoint(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<UUID, UUID>
        roleToUser content: @Sendable @escaping () -> OrderedSet<MTMRelation<UUID, UUID>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.appoint(roleToUser: content(), on: transactor)
    }
    
    func appoint(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<QRole, QUser>
        _ content: @Sendable @escaping () -> OrderedSet<MTMRelation<QRole, QUser>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.appoint(relations: content(), on: transactor)
    }
    
    func appoint(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<UUID, UUID>
        roleToGroup content: @Sendable @escaping () -> OrderedSet<MTMRelation<UUID, UUID>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.appoint(roleToGroup: content(), on: transactor)
    }
    
    func appoint(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<QRole, QGroup>
        _ content: @Sendable @escaping () -> OrderedSet<MTMRelation<QRole, QGroup>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.appoint(relations: content(), on: transactor)
    }
    
    func appoint(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<UUID, UUID>
        roleToUserInGroup content: @Sendable @escaping () -> OrderedSet<MTMRelation<UUID, UUID>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.appoint(roleToUserInGroup: content(), on: transactor)
    }
    
    func appoint(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<QRole, UserTGroup>
        _ content: @Sendable @escaping () -> OrderedSet<MTMRelation<QRole, UserTGroup>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.appoint(relations: content(), on: transactor)
    }
    
    // MARK: - 角色撤职
    
    func dismiss(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<UUID, UUID>
        roleFromUser content: @Sendable @escaping () -> OrderedSet<MTMRelation<UUID, UUID>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.dismiss(roleFromUser: content(), on: transactor)
    }
    
    func dismiss(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<QRole, QUser>
        _ content: @Sendable @escaping () -> OrderedSet<MTMRelation<QRole, QUser>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.dismiss(relations: content(), on: transactor)
    }
    
    func dismiss(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<UUID, UUID>
        roleFromGroup content: @Sendable @escaping () -> OrderedSet<MTMRelation<UUID, UUID>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.dismiss(roleFromGroup: content(), on: transactor)
    }
    
    func dismiss(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<QRole, QGroup>
        _ content: @Sendable @escaping () -> OrderedSet<MTMRelation<QRole, QGroup>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.dismiss(relations: content(), on: transactor)
    }
    
    func dismiss(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<UUID, UUID>
        roleFromUserInGroup content: @Sendable @escaping () -> OrderedSet<MTMRelation<UUID, UUID>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.dismiss(roleFromUserInGroup: content(), on: transactor)
    }
    
    func dismiss(
        on transactor: Transactor? = nil,
        @MTMRelationBuilder<QRole, UserTGroup>
        _ content: @Sendable @escaping () -> OrderedSet<MTMRelation<QRole, UserTGroup>>
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        self.dismiss(relations: content(), on: transactor)
    }
}

extension PrivilegeSystem.RoleController {
    // MARK: - 角色任命
    func appoint(
        roleToUser relations: OrderedSet<MTMRelation<UUID, UUID>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色任命用户 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色任命用户关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToManyReversed(
            on: db,
            relations,
            type: (QRole.self, QUser.self),
            action: .attach,
            label: "角色与用户",
            errThrowing: .roleAppointUserFailed,
            pivotType: __SDBM.Pivots.UserRole.self,
            checkList: .all
        )
        .map { logger.info("角色任命用户 操作成功") }
        .logIfFail(logger: logger)
    }
    
    func appoint(
        relations: OrderedSet<MTMRelation<QRole, QUser>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色任命用户 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色任命用户关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToManyReversed(
            on: db,
            relations,
            action: .attach,
            label: "角色与用户",
            errThrowing: .roleAppointUserFailed,
            pivotType: __SDBM.Pivots.UserRole.self
        )
        .map { logger.info("角色任命用户 操作成功") }
        .logIfFail(logger: logger)
    }
    
    func appoint(
        roleToGroup relations: OrderedSet<MTMRelation<UUID, UUID>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色任命用户组 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色任命用户组关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            type: (QRole.self, QGroup.self),
            action: .attach,
            label: "角色与用户组",
            errThrowing: .roleAppointGroupFailed,
            pivotType: __SDBM.Pivots.RoleGroup.self,
            checkList: .all
        )
        .map { logger.info("角色任命用户组 操作成功") }
        .logIfFail(logger: logger)
    }
    
    func appoint(
        relations: OrderedSet<MTMRelation<QRole, QGroup>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色任命用户组 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色任命用户组关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            action: .attach,
            label: "角色与用户组",
            errThrowing: .roleAppointGroupFailed,
            pivotType: __SDBM.Pivots.RoleGroup.self
        )
        .map { logger.info("角色任命用户组 操作成功") }
        .logIfFail(logger: logger)
    }
    
    func appoint(
        roleToUserInGroup relations: OrderedSet<MTMRelation<UUID, UUID>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色任命组内用户 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色任命组内用户关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            type: (QRole.self, UserTGroup.self),
            action: .attach,
            label: "角色与群组内用户",
            errThrowing: .roleAppointGroupUserFailed,
            pivotType: __SDBM.Pivots.RoleUserInGroup.self,
            checkList: .all
        )
        .map { logger.info("角色任命组内用户 操作成功") }
        .logIfFail(logger: logger)
    }
    
    func appoint(
        relations: OrderedSet<MTMRelation<QRole, UserTGroup>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色任命组内用户 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色任命组内用户关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            action: .attach,
            label: "角色与群组内用户",
            errThrowing: .roleAppointGroupUserFailed,
            pivotType: __SDBM.Pivots.RoleUserInGroup.self
        )
        .map { logger.info("角色任命组内用户 操作成功") }
        .logIfFail(logger: logger)
    }
    
    // MARK: - 角色撤职
    func dismiss(
        roleFromUser relations: OrderedSet<MTMRelation<UUID, UUID>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色撤職用户 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色撤職用户关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToManyReversed(
            on: db,
            relations,
            type: (QRole.self, QUser.self),
            action: .detach,
            label: "角色与用户",
            errThrowing: .roleDismissUserFailed,
            pivotType: __SDBM.Pivots.UserRole.self,
            checkList: .all
        )
        .map { logger.info("角色撤職用户 操作成功") }
        .logIfFail(logger: logger)
    }
    
    func dismiss(
        relations: OrderedSet<MTMRelation<QRole, QUser>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色撤職用户 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色撤職用户关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToManyReversed(
            on: db,
            relations,
            action: .detach,
            label: "角色与用户",
            errThrowing: .roleDismissUserFailed,
            pivotType: __SDBM.Pivots.UserRole.self
        )
        .map { logger.info("角色撤職用户 操作成功") }
        .logIfFail(logger: logger)
    }
    
    func dismiss(
        roleFromGroup relations: OrderedSet<MTMRelation<UUID, UUID>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色撤職用户组 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色撤職用户组关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            type: (QRole.self, QGroup.self),
            action: .detach,
            label: "角色与用户组",
            errThrowing: .roleDismissGroupFailed,
            pivotType: __SDBM.Pivots.RoleGroup.self,
            checkList: .all
        )
        .map { logger.info("角色撤職用户组 操作成功") }
        .logIfFail(logger: logger)
    }
    
    func dismiss(
        relations: OrderedSet<MTMRelation<QRole, QGroup>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色撤職用户组 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色撤職用户组关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            action: .detach,
            label: "角色与用户组",
            errThrowing: .roleDismissGroupFailed,
            pivotType: __SDBM.Pivots.RoleGroup.self
        )
        .map { logger.info("角色撤職用户组 操作成功") }
        .logIfFail(logger: logger)
    }
    
    func dismiss(
        roleFromUserInGroup relations: OrderedSet<MTMRelation<UUID, UUID>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色撤職组内用户 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色撤職组内用户关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            type: (QRole.self, UserTGroup.self),
            action: .detach,
            label: "角色与群组内用户",
            errThrowing: .roleDismissGroupUserFailed,
            pivotType: __SDBM.Pivots.RoleUserInGroup.self,
            checkList: .all
        )
        .map { logger.info("角色撤職组内用户 操作成功") }
        .logIfFail(logger: logger)
    }
    
    func dismiss(
        relations: OrderedSet<MTMRelation<QRole, UserTGroup>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 角色撤職组内用户 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("角色撤職组内用户关系详情", metadata: ["detail": .data(relations)])
        let db = transactor?.db ?? self.db
        return __manyToMany(
            on: db,
            relations,
            action: .detach,
            label: "角色与群组内用户",
            errThrowing: .roleDismissGroupUserFailed,
            pivotType: __SDBM.Pivots.RoleUserInGroup.self
        )
        .map { logger.info("角色撤職组内用户 操作成功") }
        .logIfFail(logger: logger)
    }
}

// MARK: - 角色的验证与查询

public extension PrivilegeSystem.RoleController {
    // 一个 user 可用的所有 roles 包括:
    // 1.为 user 赋予的 用户角色
    // 2.user 所在组的 群组角色，包括所有父群组的 群组角色
    // 3.user 所在组为其赋予的 组内角色
    typealias Errcase = PrivilegeSystem.Errcase
    
    func roles(
        for user: QUser,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[QRole], Errcase> {
        __roles(on: transactor?.db ?? self.db, for: user)
    }
    
    func roles(
        for userId: UUID,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[QRole], Errcase> {
        __roles(on: transactor?.db ?? self.db, for: userId)
    }
    
    func userRoles(
        for user: QUser,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[QRole], Errcase> {
        __userRoles(on: transactor?.db ?? self.db, for: user)
    }
    
    func userRoles(
        for userId: UUID,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[QRole], Errcase> {
        __userRoles(on: transactor?.db ?? self.db, for: userId)
    }
    
    func groupRoles(
        for user: QUser,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[MTORelation<QRole, QGroup>], Errcase> {
        __groupRoles(on: transactor?.db ?? self.db, for: user)
    }
    
    func groupRoles(
        for userId: UUID,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[MTORelation<QRole, QGroup>], Errcase> {
        __groupRoles(on: transactor?.db ?? self.db, for: userId)
    }
    
    func userInGroupRoles(
        for user: QUser,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[MTORelation<QRole, QGroup>], Errcase> {
        __userInGroupRoles(on: transactor?.db ?? self.db, for: user)
    }
    
    func userInGroupRoles(
        for userId: UUID,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[MTORelation<QRole, QGroup>], Errcase> {
        __userInGroupRoles(on: transactor?.db ?? self.db, for: userId)
    }
}

public extension PrivilegeSystem.RoleController {
    func `is`(
        role: QRole,
        appointedTo user: QUser,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Bool, Errcase> {
        __is(on: transactor?.db ?? self.db, role: role, appointedTo: user)
    }
    
    func `is`(
        roleId: UUID,
        appointedTo userId: UUID,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Bool, Errcase> {
        __is(on: transactor?.db ?? self.db, roleId: roleId, appointedTo: userId)
    }
    
    func `is`(
        userRole: QRole,
        appointedTo user: QUser,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Bool, Errcase> {
        __is(on: transactor?.db ?? self.db, userRole: userRole, appointedTo: user)
    }
    
    func `is`(
        userRoleId: UUID,
        appointedTo userId: UUID,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Bool, Errcase> {
        __is(on: transactor?.db ?? self.db, userRoleId: userRoleId, appointedTo: userId)
    }
    
    func `is`(
        groupRole: QRole,
        appointedTo group: QGroup,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Bool, Errcase> {
        __is(on: transactor?.db ?? self.db, groupRole: groupRole, appointedTo: group)
    }
    
    func `is`(
        groupRoleId: UUID,
        appointedTo groupId: UUID,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Bool, Errcase> {
        __is(on: transactor?.db ?? self.db, groupRoleId: groupRoleId, appointedTo: groupId)
    }
    
    func verify(
        groupRole: QRole,
        appointedTo user: QUser,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[QGroup], Errcase> {
        __verify(on: transactor?.db ?? self.db, groupRole: groupRole, appointedTo: user)
    }
    
    func verify(
        groupRoleId: UUID,
        appointedTo userId: UUID,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[QGroup], Errcase> {
        __verify(on: transactor?.db ?? self.db, groupRoleId: groupRoleId, appointedTo: userId)
    }
    
    func verify(
        userInGroupRole: QRole,
        appointedTo user: QUser,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[QGroup], Errcase> {
        __verify(on: transactor?.db ?? self.db, userInGroupRole: userInGroupRole, appointedTo: user)
    }
    
    func verify(
        userInGroupRoleId: UUID,
        appointedTo userId: UUID,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<[QGroup], Errcase> {
        __verify(on: transactor?.db ?? self.db, userInGroupRoleId: userInGroupRoleId, appointedTo: userId)
    }}


extension PrivilegeSystem.RoleController {
    // 取得 某用户 所有可用的 角色 by QUser
    func __roles(
        on db: PGDatabase,
        for user: QUser
    ) -> EventLoopRes<[QRole], Errcase> {
        [
            __userRoles(on: db, for: user),
            __groupRoles(on: db, for: user).map { $0.flatMap { $0.left } },
            __userInGroupRoles(on: db, for: user).map { $0.flatMap { $0.left } }
        ].flatten(on: db.eventLoop).map {
            [QRole]($0.flatMap { $0 }.uniqued())
        }
    }
    
    // 取得 某用户 所有可用的 角色 by id
    func __roles(
        on db: PGDatabase,
        for userId: UUID
    ) -> EventLoopRes<[QRole], Errcase> {
        [
            __userRoles(on: db, for: userId),
            __groupRoles(on: db, for: userId).map { $0.flatMap { $0.left } },
            __userInGroupRoles(on: db, for: userId).map { $0.flatMap { $0.left } }
        ].flatten(on: db.eventLoop).map {
            [QRole]($0.flatMap { $0 }.uniqued())
        }
    }
    
    // 取得 某用户 可用的所有用户角色 by QUser
    func __userRoles(
        on db: PGDatabase,
        for user: QUser
    ) -> EventLoopRes<[QRole], Errcase> {
        user.model(from: db)
            .errCast(Errcase.userRoleQueryFailed, "取得 User 主模型失败", metadata: ["user": .data(user)], category: .internal)
            .flatMap { self.__userRoles(on: db, for: $0) }
    }
    
    // 取得 某用户 可用的所有用户角色 by id
    func __userRoles(
        on db: PGDatabase,
        for userId: UUID
    ) -> EventLoopRes<[QRole], Errcase> {
        __SDBM.User.query(on: db)
            .filter(\.$id == userId)
            .first()
            .withError(Errcase.userRoleQueryFailed, "取得 User 主模型失败", metadata: ["id": .stringConvertible(userId)], category: .internal)
            .flatMap
        { user in
            guard let u = user else {
                return db.eventLoop.makeFailedResult(Errcase.userRoleQueryFailed, "要查询用户不存在", metadata: ["id": .stringConvertible(userId)], category: .external(userdata: .init(HTTPResponseStatus.notFound)))
            }
            return db.eventLoop.makeSucceededResult(u)
        }.flatMap {
            self.__userRoles(on: db, for: $0)
        }
    }
    
    // 查询某个用户的所有可用群组角色(role)，即用户所在群组被赋予的角色，包括该群组的所有父群组 by QUser
    func __groupRoles(
        on db: PGDatabase,
        for user: QUser
    ) -> EventLoopRes<[MTORelation<QRole, QGroup>], Errcase> {
        user.model(from: db)
            .errCast(Errcase.userRoleQueryFailed, "取得 User 主模型失败", metadata: ["user": .data(user)], category: .internal)
            .flatMap { self.__groupRoles(on: db, for: $0) }
    }
    
    // 查询某个用户的所有可用群组角色(role)，即用户所在群组被赋予的角色，包括该群组的所有父群组 by id
    func __groupRoles(
        on db: PGDatabase,
        for userId: UUID
    ) -> EventLoopRes<[MTORelation<QRole, QGroup>], Errcase> {
        __SDBM.User.query(on: db)
            .filter(\.$id == userId)
            .first()
            .withError(Errcase.groupRoleQueryFailed, "取得 User 主模型失败", metadata: ["id": .stringConvertible(userId)], category: .internal)
            .flatMap
        { user in
            guard let u = user else {
                return db.eventLoop.makeFailedResult(Errcase.groupRoleQueryFailed, "要查询用户不存在", metadata: ["id": .stringConvertible(userId)], category: .external(userdata: .init(HTTPResponseStatus.notFound)))
            }
            return db.eventLoop.makeSucceededResult(u)
        }.flatMap {
            self.__groupRoles(on: db, for: $0)
        }
    }
    
    // 查询某个用户的所有可用组内角色(role) by QUser
    func __userInGroupRoles(
        on db: PGDatabase,
        for user: QUser
    ) -> EventLoopRes<[MTORelation<QRole, QGroup>], Errcase> {
        __userInGroupRoles(on: db, for: user.id)
    }
    
    // 查询某个用户的所有可用组内角色(role) by Id
    func __userInGroupRoles(
        on db: PGDatabase,
        for userId: UUID
    ) -> EventLoopRes<[MTORelation<QRole, QGroup>], Errcase> {
        // 1. 第一步：捞出该用户直接加入的所有群组关系，并预加载完整的 __SDBM.Group 实体
        __SDBM.UserGroupPivot.query(on: db)
            .filter(\.$primaryModel.$id == userId)
            .with(\.$secondaryModel)
            .all()
            .withError(Errcase.userInGroupRoleQueryFailed, "从数据库查询失败", category: .internal)
            .flatMapThrowing
        { userGroupPivots throws(Errcase.ErrType) in
            // 安全提取所有“用户-群组”关系表的主键 ID (UUID)
            try required(throws: Errcase.userInGroupRoleQueryFailed, "用户群组 pivot 的 id 获取失败", category: .internal) {
                let pivotIds = try userGroupPivots.map { try $0.requireID() }
                return (userGroupPivots, pivotIds)
            }
        }.flatMap { (userGroupPivots: [__SDBM.UserGroupPivot], pivotIds: [UUID]) in
            guard !pivotIds.isEmpty else {
                return db.eventLoop.makeSucceededResult([])
            }
            
            // 2. 第二步：一发 IN 聚合查询，直击二级中间表
            return __SDBM.RoleUserInGroupPivot.query(on: db)
                .filter(\.$secondaryModel.$id ~~ pivotIds)
                .with(\.$primaryModel)
                .all()
                .withError(Errcase.userInGroupRoleQueryFailed, "从数据库取得 pivot 失败", category: .internal)
                .flatMapThrowing
            { pivots throws(Errcase.ErrType) in
                try required(throws: Errcase.userInGroupRoleQueryFailed, "转为 DTO 失败", category: .internal) {
                    
                    // 3. 第三步：为了做到 O(1) 的内存装配性能，先把第一步查到的物理实体织成一张“查找表”
                    // Key 是 UserGroupPivot 的 ID，Value 是完整的 __SDBM.Group 实体
                    var pivotToGroupLookup: [UUID: __SDBM.Group] = [:]
                    for ugPivot in userGroupPivots {
                        if let ugPivotId = ugPivot.id {
                            pivotToGroupLookup[ugPivotId] = ugPivot.secondaryModel
                        }
                    }
                    
                    // 4. 第四步：在内存里，把多条角色记录按照【群组自身的 ID】重新切分团聚
                    let groupedByGroup = try Dictionary(grouping: pivots, by: { pivot -> UUID in
                        // 凭借当前记录的 user_in_group_id，从刚才的查找表里瞬间拿到 group.id
                        guard let g = pivotToGroupLookup[pivot.$secondaryModel.id], let gId = g.id else {
                            throw Errcase.userInGroupRoleQueryFailed.d("组内角色纽带关系映射丢失", category: .internal)
                        }
                        return gId
                    })
                    
                    // 5. 第五步：组装出符合你多对一泛型要求的 MTORelation 数组
                    return try groupedByGroup.map { groupId, currentPivots in
                        
                        // 5.1 从刚才建好的查找表里，把那个直接加入的完整的 __SDBM.Group 实体揪出来
                        // 由于同一个 groupId 对应的 __SDBM.Group 是一样的，我们直接拿 currentPivots 第一个对应的组即可
                        let samplePivotId = currentPivots[0].$secondaryModel.id
                        guard let associatedGroup = pivotToGroupLookup[samplePivotId] else {
                            throw Errcase.userInGroupRoleQueryFailed.d("群组实体检索失败", category: .internal)
                        }
                        
                        let groupDTO = try QGroup.make(from: associatedGroup).get()
                        
                        // 5.2 把这个组名下被特殊指派的所有角色批量映射为 Role DTO，并做内存去重
                        let roleDTOs = try Array(currentPivots.map { pivot in
                            try QRole.make(from: pivot.primaryModel).get()
                        }.uniqued())
                        
                        // 5.3 完美打包塞入多对一容器
                        return MTORelation(
                            left: .init(roleDTOs), // 该用户在这个组内被指派的多个专属角色
                            right: groupDTO // 指派来源的直接群组（一端）
                        )
                    }
                }
            }
        }
    }
}

extension PrivilegeSystem.RoleController {
    // 取得 某用户 可用的所有用户角色
    func __userRoles(
        on db: PGDatabase,
        for user: __SDBM.User
    ) -> EventLoopRes<[QRole], Errcase> {
        user.$roles.get(on: db)
            .withError(Errcase.userRoleQueryFailed, "从数据库查询失败", category: .internal)
            .flatMapThrowing
        { userRoles throws(Errcase.ErrType) in
            try required(throws: Errcase.userRoleQueryFailed, "转为 DTO 失败", category: .internal) {
                try userRoles.map { try QRole.make(from: $0).get() }
            }
        }
    }
    
    // 查询某个用户的所有可用群组角色(role)，即用户所在群组被赋予的角色，包括该群组的所有父群组
    func __groupRoles(
        on db: PGDatabase,
        for user: __SDBM.User
    ) -> EventLoopRes<[MTORelation<QRole, QGroup>], Errcase> {
        user.$groups.query(on: db)
            .with(\.$supers) { path in
                path.with(\.$ancestor)
            }
            .all()
            .withError(Errcase.groupRoleQueryFailed, "从数据库查询失败", category: .internal)
        .flatMapThrowing { groupRoles throws(Errcase.ErrType) in
            let gs = [__SDBM.Group]((
                groupRoles +
                groupRoles.flatMap { $0.supers.map { $0.ancestor } }
            ).uniqued())
            
            // 安全提取所有唯一的群组 UUID 集合
            let ids = try required(throws: Errcase.arbitrateFailed, "取得群组 ID 失败", category: .internal) {
                try gs.map { try $0.requireID() }
            }
            
            return (gs, ids)
        }.flatMap { (groups: [__SDBM.Group], groupIds: [UUID]) in
            guard !groupIds.isEmpty else {
                return db.eventLoop.makeSucceededResult([])
            }
            
            return __SDBM.RoleGroupPivot.query(on: db)
                .filter(\.$secondaryModel.$id ~~ groupIds)
                .with(\.$primaryModel)
                .all()
                .withError(Errcase.groupRoleQueryFailed, "取得 Role Pivot 数据失败", category: .internal)
                .flatMapThrowing
            { pivots throws(Errcase.ErrType) in
                try required(throws: Errcase.groupRoleQueryFailed, "转为 DTO 失败", category: .internal) {
                    // 在内存中把分散的 pivots 记录按照「群组的 UUID」切分揉合在一起
                    // 得到的字典：[Group_UUID: [Pivot]]
                    let groupedPivots = Dictionary(grouping: pivots, by: { $0.$secondaryModel.id })
                    
                    // 遍历聚合后的字典，组装成多对一结构的 MTORelation 数组
                    return try groupedPivots.map { groupId, currentGroupPivots in
                        guard let associatedGroup = groups.first(where: { $0.id == groupId }) else {
                            throw Errcase.groupRoleQueryFailed.d("群组数据映射丢失", category: .internal)
                        }
                        
                        let groupDTO = try QGroup.make(from: associatedGroup).get()
                        let roleDTOs = [QRole](try currentGroupPivots.map { pivot in
                            try QRole.make(from: pivot.primaryModel).get()
                        }.uniqued())
                        
                        return MTORelation(
                            left: .init(roleDTOs),
                            right: groupDTO
                        )
                    }
                }
            }
        }
    }
}

extension PrivilegeSystem.RoleController {
    // 检查某角色对于某用户是否可用 by QRole and QUser
    func __is(
        on db: PGDatabase,
        role: QRole,
        appointedTo user: QUser
    ) -> EventLoopRes<Bool, Errcase> {
        [
            __is(on: db, userRole: role, appointedTo: user),
            __verify(on: db, groupRole: role, appointedTo: user).map { !$0.isEmpty },
            __verify(on: db, userInGroupRole: role, appointedTo: user).map { !$0.isEmpty }
        ].flatten(on: db.eventLoop).map { $0.reduce(false) { $0 || $1 } }
    }
    
    // 检查某角色对于某用户是否可用 by id
    func __is(
        on db: PGDatabase,
        roleId: UUID,
        appointedTo userId: UUID
    ) -> EventLoopRes<Bool, Errcase> {
        [
            __is(on: db, userRoleId: roleId, appointedTo: userId),
            __verify(on: db, groupRoleId: roleId, appointedTo: userId).map { !$0.isEmpty },
            __verify(on: db, userInGroupRoleId: roleId, appointedTo: userId).map { !$0.isEmpty }
        ].flatten(on: db.eventLoop).map { $0.reduce(false) { $0 || $1 } }
    }
    
    // 检查某角色是否被任命某用户 by QRole and QUser
    func __is(
        on db: PGDatabase,
        userRole: QRole,
        appointedTo user: QUser
    ) -> EventLoopRes<Bool, Errcase> {
        dtoModelToSQLModel(on: db, model: user, errThrowing: .groupRoleVerifyFailed)
            .flatMap { self.__is(on: db, userRoleId: userRole.id, appointedTo: $0) }
    }
    
    // 检查某角色是否被任命某用户 by id
    func __is(
        on db: PGDatabase,
        userRoleId: UUID,
        appointedTo userId: UUID
    ) -> EventLoopRes<Bool, Errcase> {
        idToSQLModel(on: db, builder: __SDBM.User.query(on: db), id: userId, errThrowing: .groupRoleVerifyFailed)
            .flatMap { self.__is(on: db, userRoleId: userRoleId, appointedTo: $0) }
    }
    
    // 检查某角色是否被任命某群组为群组角色 by QRole and QGroup
    func __is(
        on db: PGDatabase,
        groupRole: QRole,
        appointedTo group: QGroup
    ) -> EventLoopRes<Bool, Errcase> {
        dtoModelToSQLModel(on: db, model: group, errThrowing: .groupRoleCheckFailed)
            .flatMap { self.__is(on: db, groupRoleId: groupRole.id, appointedTo: $0) }
    }
    
    // 检查某角色是否被任命某群组为群组角色 by id
    func __is(
        on db: PGDatabase,
        groupRoleId: UUID,
        appointedTo groupId: UUID
    ) -> EventLoopRes<Bool, Errcase> {
        idToSQLModel(on: db, builder: __SDBM.Group.query(on: db), id: groupId, errThrowing: .groupRoleCheckFailed)
            .flatMap { self.__is(on: db, groupRoleId: groupRoleId, appointedTo: $0) }
    }
    
    // 验证某群组角色是否为某用户可用，若可用，指出该角色是哪个或哪些群组的群组角色 by QUser and QRole
    func __verify(
        on db: PGDatabase,
        groupRole: QRole,
        appointedTo user: QUser
    ) -> EventLoopRes<[QGroup], Errcase> {
        dtoModelToSQLModel(on: db, model: user, errThrowing: .groupRoleVerifyFailed)
            .flatMap { self.__verify(on: db, groupRoleId: groupRole.id, appointedTo: $0) }
    }
    
    // 验证某群组角色是否为某用户可用，若可用，指出该角色是哪个或哪些群组的群组角色 by Id
    func __verify(
        on db: PGDatabase,
        groupRoleId: UUID,
        appointedTo userId: UUID
    ) -> EventLoopRes<[QGroup], Errcase> {
        idToSQLModel(on: db, builder: __SDBM.User.query(on: db), id: userId, errThrowing: .groupRoleVerifyFailed)
            .flatMap { self.__verify(on: db, groupRoleId: groupRoleId, appointedTo: $0) }
    }
    
    // 验证某组内角色是否为某用户可用，若可用，指出该角色是哪个或哪些群组的群组角色 by QUser and QRole
    func __verify(
        on db: PGDatabase,
        userInGroupRole: QRole,
        appointedTo user: QUser
    ) -> EventLoopRes<[QGroup], Errcase> {
        __verify(on: db, userInGroupRoleId: userInGroupRole.id, appointedTo: user.id)
    }
    
    // 验证某组内角色是否为某用户可用，若可用，指出该角色是哪个或哪些群组的群组角色 by Id
    func __verify(
        on db: PGDatabase,
        userInGroupRoleId: UUID,
        appointedTo userId: UUID
    ) -> EventLoopRes<[QGroup], Errcase> {
        __SDBM.RoleUserInGroupPivot.query(on: db)
            .filter(\.$primaryModel.$id == userInGroupRoleId)
            .join(__SDBM.UserGroupPivot.self, on: \__SDBM.RoleUserInGroupPivot.$secondaryModel.$id == \__SDBM.UserGroupPivot.$id)
            .filter(__SDBM.UserGroupPivot.self, \.$primaryModel.$id == userId)
            .with(\.$secondaryModel) { userInGroup in
                // 通过 eager load，强行把内层中间表，以及中间表背后的 __SDBM.Group 实体全部批量捎带出来
                userInGroup.with(\.$secondaryModel)
            }
            .all()
            .withError(Errcase.userInGroupRoleVerifyFailed, "验证组内特指派角色可用性失败", category: .internal)
            .flatMapThrowing
        { pivots throws(Errcase.ErrType) in
            try required(throws: Errcase.userInGroupRoleVerifyFailed, "转为 DTO 失败", category: .internal) {
                // 穿透复合中间表，抓出最内层的 __SDBM.Group 并映射为 Group DTO
                try pivots.map { pivot -> QGroup in
                    // 1. 从二级表拿到内层表 UserGroupPivot
                    let userGroupRelation = pivot.secondaryModel
                    // 2. 从内层表拿到我们刚刚用 .with(\.$group) 提前预加载好的 __SDBM.Group 物理实体
                    let rawGroup = userGroupRelation.secondaryModel
                    // 3. 完美转化为安全、干净的 DTO.Group 容器交付出去
                    return try QGroup.make(from: rawGroup).get()
                }
            }
        }
    }
}

extension PrivilegeSystem.RoleController {
    // 检查某角色是否被任命某用户
    func __is(
        on db: PGDatabase,
        userRoleId: UUID,
        appointedTo user: __SDBM.User
    ) -> EventLoopRes<Bool, Errcase> {
        user.$roles.query(on: db)
            .filter(\.$id == userRoleId)
            .first()
            .withError(Errcase.userRoleCheckFailed, "从数据库查询失败", category: .internal)
            .map { $0 != nil }
    }
    
    // 检查某角色是否被任命某群组为群组角色
    func __is(
        on db: PGDatabase,
        groupRoleId: UUID,
        appointedTo group: __SDBM.Group
    ) -> EventLoopRes<Bool, Errcase> {
        group.$groupRoles.query(on: db)
            .filter(\.$id == groupRoleId)
            .first()
            .withError(Errcase.groupRoleCheckFailed, "从数据库查询失败", category: .internal)
            .map { $0 != nil }
    }
    
    // 验证某群组角色是否为某用户可用，若可用，指出该角色是哪个或哪些群组的群组角色
    func __verify(
        on db: PGDatabase,
        groupRoleId: UUID,
        appointedTo user: __SDBM.User
    ) -> EventLoopRes<[QGroup], Errcase> {
        user.$groups.query(on: db)
            .with(\.$supers) { path in
                path.with(\.$ancestor)
            }
            .all()
            .withError(Errcase.groupRoleVerifyFailed, "取得用户所加入的所有群组失败", category: .internal)
            .flatMap
        { groups in
            let gs = [__SDBM.Group]((
                groups +
                groups.flatMap { $0.supers.map { $0.ancestor } }
            ).uniqued())
            
            let groupIds = gs.compactMap { $0.id }
            
            guard !groupIds.isEmpty else {
                return db.eventLoop.makeSucceededResult([])
            }
            
            let groupsLookup = Dictionary(uniqueKeysWithValues: gs.map { ($0.id, $0) })
            
            return __SDBM.RoleGroupPivot.query(on: db)
                .filter(\.$primaryModel.$id == groupRoleId)
                .filter(\.$secondaryModel.$id ~~ groupIds)
                .all()
                .withError(Errcase.groupRoleVerifyFailed, "校验群组角色关联失败", category: .internal)
                .flatMapThrowing
            { pivots throws(Errcase.ErrType) in
                try required(throws: Errcase.groupRoleVerifyFailed, "转为 DTO 失败", category: .internal) {
                    // 逆向匹配，把中间表捞出来的关联群组 ID 还原为完整的 Group DTO
                    try pivots.compactMap { pivot -> QGroup? in
                        let pivotGroupId = pivot.$secondaryModel.id
                        
                        // 凭借外键 ID 从刚才的 lookup 字典中 O(1) 瞬间揪出原生态的、带树状血缘的 __SDBM.Group 实体
                        guard let associatedGroup = groupsLookup[pivotGroupId] else { return nil }
                        
                        // 将其整装转换为你需要的 DTO.Group 并交付出去
                        return try QGroup.make(from: associatedGroup).get()
                    }
                }
            }
        }
    }
    
    func idToSQLModel<T: PGModel>(
        on db: PGDatabase,
        builder: QueryBuilder<T>,
        id: UUID,
        errThrowing: Errcase
    ) -> EventLoopRes<T, Errcase> {
        builder
            .filter(.id, .equal, id)
            .first()
            .withError(errThrowing, "取得 \(T.name) 主模型失败", metadata: ["id": .stringConvertible(id)], category: .internal)
            .flatMap
        { user in
            guard let u = user else {
                return db.eventLoop.makeFailedResult(errThrowing, "要查询的 \(T.name) 不存在", metadata: ["id": .stringConvertible(id)], category: .external(userdata: .init(HTTPResponseStatus.notFound)))
            }
            return db.eventLoop.makeSucceededResult(u)
        }
    }
    
    func dtoModelToSQLModel<T: __DBModel>(
        on db: PGDatabase,
        model: T,
        errThrowing: Errcase
    ) -> EventLoopRes<T.SQLModel, Errcase> {
        model.model(from: db)
            .errCast(errThrowing, "取得 \(T.logName) 主模型失败", metadata: ["model": .data(model)], category: .internal)
    }
}

extension PrivilegeSystem.RoleController {
    public func __create(
        on db: PGDatabase,
        roles: OrderedSet<PRole>,
        noReservedName: Bool
    ) -> EventLoopRes<[QRole], PrivilegeSystem.Errcase> {
        if !noReservedName {
            var badNames: [String] = []
            for role in roles {
                if (self.reservedRoleName.contains(role.name)) {
                    badNames.append(role.name)
                }
            }
            
            guard badNames.isEmpty else {
                return db.eventLoop.makeFailedResult(PrivilegeSystem.Errcase.roleCreateFailed, "\"\(badNames.joined(separator: "\", \""))\" 均为保留名称，不可作为角色名称", category: .external(suggestions: ["请选择非保留字的名称作为角色名称"], userdata: .init(HTTPResponseStatus.unprocessableEntity)))
            }
        }
        
        return __create(
            on: db,
            dtos: roles,
            label: "角色",
            errThrowing: .roleCreateFailed,
            modelBuilder: { .success($0.raw()) },
            dtoBuilder: { QRole.make(from: $0.fill()) }
        )
    }
}
