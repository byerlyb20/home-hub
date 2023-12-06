const sqlite3 = require('sqlite3')

var db

function connect(path) {
    db = new sqlite3.Database(path)
}

class DatabaseError extends Error {

    statusCode = 400

    constructor(sqliteErrorCode, ...params) {
        const message = `SQLite3 Database Error: ${sqliteErrorCode}`
        super(message, ...params)
        this.sqliteErrorCode = sqliteErrorCode
    }
}

const run = ((...params) => new Promise((resolve, reject) => {
    db.run(...params, function (error) {
        if (error) {
            reject(new DatabaseError(error))
        } else {
            resolve(this.lastID)
        }
    })
}))

const get = ((...params) => new Promise((resolve, reject) => {
    db.get(...params, function (error, row) {
        if (error) {
            reject(new DatabaseError(error))
        } else {
            resolve(row)
        }
    })
}))

const createNewUser = ((username, challenge, challengeExpiry) =>
    run(`INSERT INTO Users (
            Username,
            Challenge,
            ChallengeExpiry)
        VALUES (?, ?, ?);`, username, challenge, challengeExpiry))

const getUserChallenge = (async (userID) => {
    let row = await get(`SELECT Challenge, ChallengeExpiry
                         FROM Users
                         WHERE Id=?`, userID)
    if (row === undefined) return undefined
    return [row['Challenge'], row['ChallengeExpiry']]
})

const savePasskey = ((passkeyID, userID, publicKey, createdOn) =>
    run(`INSERT INTO Passkeys (
            Id,
            UserId,
            PublicKey,
            CreatedOn)
        VALUES (?, ?, ?, ?);`, passkeyID, userID, publicKey, createdOn))

const saveSessionChallenge = ((challenge, challengeExpiry) => {
    challenge = cleanseBase64(challenge)
    return run(`INSERT INTO Sessions (
            Challenge,
            ChallengeExpiry)
        VALUES (?, ?);`, challenge, challengeExpiry)
})

const getPasskey = (async (passkeyID) => {
    let row = await get(`SELECT Users.Username, Users.Id, Passkeys.PublicKey
                   FROM Passkeys
                   INNER JOIN Users ON Passkeys.UserId = Users.Id
                   WHERE Passkeys.Id=?;`, passkeyID)
    if (row === undefined) return undefined
    return [row['Username'], row['Id'], row['PublicKey']]
})

const getSessionID = (async (challenge) => {
    challenge = cleanseBase64(challenge)
    let row = await get(`SELECT rowid, ChallengeExpiry
                         FROM Sessions
                         WHERE Challenge=?;`, challenge)
    if (row === undefined) return undefined
    return [row['rowid'], row['ChallengeExpiry']]
})

const getSession = (async (token) => {
    token = cleanseBase64(token)
    let row = await get(`SELECT Users.Id, Users.Username, Users.Permissions, Sessions.Expires
                         FROM Sessions
                         INNER JOIN Users ON Sessions.UserId = Users.Id
                         WHERE Token=?;`, token)
    if (row === undefined) return undefined
    return [row['Id'], row['Username'], row['Permissions'], row['Expires']]
})

const instateSession = ((token, userID, expires, sessionID) => {
    token = cleanseBase64(token)
    return run(`UPDATE Sessions
        SET Challenge=NULL, ChallengeExpiry=NULL, Token=?, UserId=?, Expires=?
        WHERE rowid=?`, token, userID, expires, sessionID)
})

const deleteSession = (token) =>
    run(`DELETE FROM Sessions WHERE Token=?`, token)

const instateOAuthToken = (tokenHash, friendlyName, clientID, userID,
    permissions, expires) => run(`
    INSERT INTO Tokens (
        TokenHash,
        FriendlyName,
        ClientId,
        UserId,
        TokenPermissions,
        CreatedOn,
        Expires
    )
    VALUES (?, ?, ?, ?, ?, unixepoch(), ?);`, tokenHash, friendlyName,
    clientID, userID, permissions, expires)

const getOAuthTokenInfo = ((tokenHash) => {
    tokenHash = cleanseBase64(tokenHash)
    return get(`SELECT Users.Id, Users.Username, Users.Permissions,
                            Tokens.TokenPermissions, Tokens.Expires
                            FROM TOKENS
                            INNER JOIN Users ON Tokens.UserId = Users.Id
                            WHERE TokenHash=?;`, tokenHash)
})

const AUTHORIZATION_TYPE_TOKEN = 0
const AUTHORIZATION_TYPE_PASSKEY = 1

const instateOneTimeAuthorization = (tokenHash, type, userID, permissions) =>
    run(`INSERT INTO Authorizations (
            TokenHash,
            Type,
            UserId,
            Permissions)
         VALUES (?, ?, ?, ?);`, tokenHash, type, userID, permissions)

function cleanseBase64(a) {
    // Consider using the crypto sqlean extension (would require migration to better-sqlite3)
    // https://github.com/nalgeon/sqlean/blob/main/docs/install.md#install-nodejs
    return Buffer.from(a, 'base64').toString('base64')
}

module.exports = {
    connect,
    createNewUser,
    getUserChallenge,
    savePasskey,
    saveSessionChallenge,
    getPasskey,
    getSessionID,
    getSession,
    instateSession,
    deleteSession,
    instateOAuthToken,
    getOAuthTokenInfo,
    AUTHORIZATION_TYPE_TOKEN,
    AUTHORIZATION_TYPE_PASSKEY,
    instateOneTimeAuthorization
}