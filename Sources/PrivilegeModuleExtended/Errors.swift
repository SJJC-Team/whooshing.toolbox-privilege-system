import ErrorHandle

public extension PrivilegeModuleExtended {
    enum Errcase: String, ErrList {
        case userDTOFailed = "用户数据 DTO 处理失败"
        case userInfoDTOFailed = "用户信息数据 DTO 处理失败"
        case tokenDTOFailed = "口令数据 DTO 处理失败"
        case roleDTOFailed = "角色数据 DTO 处理失败"
        case groupDTOFailed = "用户群组数据 DTO 处理失败"
        case domainDTOFailed = "域权限数据 DTO 处理失败"
        case userInGroupDTOFailed = "用户群组关系数据 DTO 处理失败"
        
        case domainGroupDTOFailed = "域-群组 关系 DTO 处理失败"
        case roleGroupDTOFailed = "角色-群组 关系 DTO 处理失败"
        case roleUserInGroupDTOFailed = "角色-组内用户 关系 DTO 处理失败"
        case userDomainDTOFailed = "用户-域 关系 DTO 处理失败"
        case userGroupDTOFailed = "用户-群组 关系 DTO 处理失败"
        case userRoleDTOFailed = "用户-角色 关系 DTO 处理失败"
        
        case policyDTORawCreateFailed = "策略数据 DTO 创建失败"
        case infoSliceDTORawCreateFailed = "用户扩展信息数据 DTO 创建失败"
        
        case tokenVerifyFailed = "用户口令验证失败"
        case roleNameIlligel = "角色名称非法"
    }
}
