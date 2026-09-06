import Foundation
import PrivilegeModule

// MARK: - UserInfoController Concurrency (UserInfoController.swift)

extension PrivilegeSystem.UserInfoController {
    public func create(
        on transactor: Transactor? = nil,
        @OTOChainRelationBuilder<UUID, PUserInfo, PExtendedInfo>
        _ content: @Sendable @escaping () -> OrderedSet<OTORelation<UUID, OTORelation<PUserInfo, PExtendedInfo>>>
    ) async throws(PrivilegeSystem.Errcase.ErrType) {
        try await create(on: transactor, content).get()
    }

    public func delete(
        infoIds: OrderedSet<UUID>,
        on transactor: Transactor? = nil
    ) async throws(PrivilegeSystem.Errcase.ErrType) {
        try await delete(infoIds: infoIds, on: transactor).get()
    }

    @discardableResult
    public func update(
        with updater: PUserInfo.Updater,
        on transactor: Transactor? = nil
    ) async throws(PrivilegeSystem.Errcase.ErrType) -> QUserInfo {
        try await update(with: updater, on: transactor).get()
    }

    public func create(
        relations: OrderedSet<OTORelation<UUID, OTORelation<PUserInfo, PExtendedInfo>>>,
        on transactor: Transactor? = nil
    ) async throws(PrivilegeSystem.Errcase.ErrType) {
        try await create(relations: relations, on: transactor).get()
    }
}
