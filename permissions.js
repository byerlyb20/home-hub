const PERMISSION_MANAGE_ACCT = 1
const PERMISSION_ISSUE_API_TOKEN = 2
const PERMISSION_ISSUE_REFRESH_TOKEN = 4
const PERMISSION_ISSUE_ACCESS_TOKEN = 8
const PERMISSION_ACCOUNT_ACTOR = 256

const PERMISSIONS_USER = PERMISSION_MANAGE_ACCT | PERMISSION_ISSUE_API_TOKEN |
    PERMISSION_ISSUE_REFRESH_TOKEN | PERMISSION_ISSUE_ACCESS_TOKEN |
    PERMISSION_ACCOUNT_ACTOR
const PERMISSIONS_API_TOKEN = PERMISSION_ACCOUNT_ACTOR
const PERMISSIONS_OAUTH_AUTHORIZATION = PERMISSION_ISSUE_REFRESH_TOKEN |
    PERMISSION_ISSUE_ACCESS_TOKEN
const PERMISSIONS_REFRESH_TOKEN = PERMISSION_ISSUE_ACCESS_TOKEN
const PERMISSIONS_ACCESS_TOKEN = PERMISSION_ACCOUNT_ACTOR

class AuthorizationError extends Error {
    statusCode = 401
}

function assertPermission(permission, ...permissionChecks) {
    let standard = 0
    for (let i = 0; i < permissionChecks.length; i++) {
        standard |= permissionChecks[i]
    }
    if ((permission & standard) != standard) {
        throw new AuthorizationError()
    }
}

function assertUserPermission(user, ...args) {
    let permission = user?.permissions
    if (permission === null || permission === undefined) {
        throw new AuthorizationError()
    } else {
        return assertPermission(permission, ...args)
    }
}

module.exports = {
    PERMISSION_MANAGE_ACCT,
    PERMISSION_ISSUE_API_TOKEN,
    PERMISSION_ISSUE_REFRESH_TOKEN,
    PERMISSION_ISSUE_ACCESS_TOKEN,
    PERMISSION_ACCOUNT_ACTOR,
    PERMISSIONS_USER,
    PERMISSIONS_API_TOKEN,
    PERMISSIONS_OAUTH_AUTHORIZATION,
    PERMISSIONS_REFRESH_TOKEN,
    PERMISSIONS_ACCESS_TOKEN,
    AuthorizationError,
    assertPermission,
    assertUserPermission
}