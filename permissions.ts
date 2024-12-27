import { User } from "./models"

export type Permissions = number

export enum Permission {
    ManageAccount = 1,
    IssueApiToken = 2,
    IssueRefreshToken = 4,
    IssueAccessToken = 8,
    AccountActor = 256
}

export namespace Permissions {
    export const USER = Permission.ManageAccount | Permission.IssueApiToken |
        Permission.IssueRefreshToken | Permission.IssueAccessToken |
        Permission.AccountActor
    export const API_TOKEN = Permission.AccountActor
    export const OAUTH_AUTHORIZATION = Permission.IssueRefreshToken |
        Permission.IssueAccessToken
    export const REFRESH_TOKEN = Permission.IssueAccessToken
    export const ACCESS_TOKEN = Permission.AccountActor
}

export class AuthorizationError extends Error {
    statusCode = 401
}

export function assertPermission(permission: Permissions, ...permissionChecks: Permissions[]) {
    let standard = 0
    for (let i = 0; i < permissionChecks.length; i++) {
        standard |= permissionChecks[i]
    }
    if ((permission & standard) != standard) {
        throw new AuthorizationError()
    }
}

export function assertUserPermission(user: (User | null | undefined), ...args: Permissions[]): User {
    let permission = user?.permissions
    if (!permission) {
        throw new AuthorizationError()
    } else {
        assertPermission(permission, ...args)
        return user as User
    }
}