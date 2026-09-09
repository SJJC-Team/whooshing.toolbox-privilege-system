import Query
import Foundation
import NIOHTTP1
import PrivilegeModule

extension PrivilegeSystem {
    /// 用户信息控制器，负责管理用户的基本和扩展信息（UserInfo）。
    ///
    /// 允许用户具备多样化的资料存储（例如生日、性别、姓名等），并且支持通过
    /// `InfoSliceController` 附带更深层次的扩展切片数据（如多个电话号码、多个备用邮箱）。
    ///
    /// - `create`: 一次性创建某用户的资料及所有扩展切片数据。
    /// - `update`: 更新用户主信息的元数据。
    /// - `delete`: 删除特定用户信息。
    public final class UserInfoController: SystemController {
        package let db: PGDatabase
        package let eventLoop: EventLoop
        
        let infoSliceController: InfoSliceController
        
        /// 操作记录日志器。
        public let logger: Logger
        
        init(
            db: PGDatabase,
            eventLoop: EventLoop,
            infoSliceController: InfoSliceController,
            logger: Logger
        ) {
            self.db = db
            self.eventLoop = eventLoop
            self.infoSliceController = infoSliceController
            self.logger = logger
        }
        
        /// 创建带有附加切片信息的完整用户档案。
        ///
        /// 允许为特定的用户指派一个综合的配置集，包含了主表的 `UserInfo` 及附表 `ExtendedInfo` 
        /// （邮箱、电话、住址切片等）。
        ///
        /// - Parameter content: `OTOChainRelationBuilder` 构建链式关系的闭包。
        /// - Returns: `EventLoopRes<Void, Errcase>`
        public func create(
            on transactor: Transactor? = nil,
            @OTOChainRelationBuilder<UUID, PUserInfo, PExtendedInfo>
            _ content: @Sendable @escaping () ->OrderedSet<OTORelation<UUID, OTORelation<PUserInfo, PExtendedInfo>>>
        ) -> EventLoopRes<Void, Errcase> {
            create(relations: content(), on: transactor)
        }
        
        /// 根据 ID 批量删除用户信息记录。
        ///
        /// - Parameters:
        ///   - infoIds: 要删除的信息记录 UUID 列表。
        /// - Returns: `EventLoopRes<Void, Errcase>`
        public func delete(
            infoIds: OrderedSet<UUID>,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<Void, Errcase> {
            let logger = getActionLogger()
            logger.info("执行 删除用户信息 操作", metadata: ["infoIds": .summaryData(infoIds)])
            logger.debug("操作参数", metadata: ["infoIds": .data(infoIds)])
            let db = transactor?.db ?? self.db
            return __delete(
                on: db,
                QUserInfo.self,
                ids: infoIds,
                label: "用户信息",
                errThrowing: .userInfoDeleteFailed,
                fieldBuilder: { $0.field(\.$id) },
                filterBuilder: { $0.filter(\.$id ~~ infoIds) }
            )
            .map { _ in logger.info("删除用户信息 操作成功") }
            .logIfFail(logger: logger)
        }
        
        /// 更新用户信息主表字段。
        ///
        /// - Parameter updater: `PUserInfo.Updater` 对象。
        /// - Returns: 更新完成的 `QUserInfo`。
        public func update(
            with updater: PUserInfo.Updater,
            on transactor: Transactor? = nil
        ) -> EventLoopRes<QUserInfo, Errcase> {
            let logger = getActionLogger()
            logger.info("执行 更新用户信息 操作", metadata: ["data": .summaryData(updater)])
            logger.debug("更新用户信息 详细请求数据", metadata: ["data": .data(updater)])
            let db = transactor?.db ?? self.db
            return __update(
                on: db,
                updater: updater,
                label: "用户信息",
                errThrowing: .userInfoUpdateFailed,
                filterBuilder: { $0.filter(\.$id == updater.userInfoId) },
                dtoBuilder: { QUserInfo.make(from: $0) }
            )
            .map { 
                logger.info("更新用户信息 操作成功", metadata: ["data": .summaryData($0)])
                logger.debug("更新用户信息 结果详细数据", metadata: ["data": .data($0)])
                return $0 
            }
            .logIfFail(logger: logger)
        }
    }
}

public extension PrivilegeSystem.UserInfoController {
    func create(
        relations:OrderedSet<OTORelation<UUID, OTORelation<PUserInfo, PExtendedInfo>>>,
        on transactor: Transactor? = nil
    ) -> EventLoopRes<Void, PrivilegeSystem.Errcase> {
        let logger = getActionLogger()
        logger.info("执行 创建用户信息 操作", metadata: ["relations": .summaryData(relations)])
        logger.debug("操作参数", metadata: ["relations": .data(relations)])
        let db = transactor?.db ?? self.db
        return db.trans(throws: .userInfoCreateFailed, "数据库事务执行失败", category: .internal) { db in
            let infos = relations.map { $0.right.left.raw(for: $0.left) }
            
            return __SDBM.User.Info.query(on: db)
                .filter(\.$user.$id ~~ infos.map { $0.$user.id })
                .with(\.$user)
                .all()
                .withError(PrivilegeSystem.Errcase.userInfoCreateFailed, "数据库查询 UserInfo 失败", category: .internal)
                .flatMap
            { dbInfos in
                guard dbInfos.isEmpty else {
                    return db.eventLoop.makeFailedResult(PrivilegeSystem.Errcase.userInfoCreateFailed, "用户信息 \"\(dbInfos.map { $0.user.email }.joined(separator: "\", \""))\" 已经存在，创建失败", category: .external(suggestions: ["一个用户仅允许创建一个用户信息", "请考虑更新而非创建"], userdata: .init(HTTPResponseStatus.conflict)))
                }
                return db.eventLoop.makeSucceededVoidResult()
            }.flatMap {
                infos
                    .create(on: db)
                    .withError(PrivilegeSystem.Errcase.userInfoCreateFailed, "数据库执行创建失败", category: .internal)
                    .flatMap
                {
                    relations.enumerated().flatMap { (i, relation) in
                        [
                            self.infoSliceController.__create(
                                on: db,
                                for: try! infos[i].requireID(),
                                extendedInfos: relation.right.right.addresses
                            ).map { _ in },
                            
                            self.infoSliceController.__create(
                                on: db,
                                for: try! infos[i].requireID(),
                                extendedInfos: relation.right.right.alternateEmails
                            ).map { _ in },
                            
                            self.infoSliceController.__create(
                                on: db,
                                for: try! infos[i].requireID(),
                                extendedInfos: relation.right.right.phones
                            ).map { _ in }
                        ]
                    }
                    .flatten(on: db.eventLoop)
                }
            }
        }
        .map { logger.info("创建用户信息 操作成功") }
        .logIfFail(logger: logger)
    }
}
