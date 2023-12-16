const sqlite3 = require('sqlite3')

let db

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

const savePasskey = ((passkeyID, userID, publicKey) =>
    run(`INSERT INTO Passkeys (
            Id,
            UserId,
            PublicKey)
        VALUES (?, ?, ?);`, passkeyID, userID, publicKey))

const saveSessionChallenge = ((challenge, challengeExpiry) => {
    return run(`INSERT INTO Sessions (
            Challenge,
            ChallengeExpiry)
        VALUES (?, ?);`, challenge, challengeExpiry)
})

const getPasskey = (passkeyID) =>
    get(`SELECT Users.Username, Passkeys.UserId, Passkeys.PublicKey
         FROM Passkeys
         INNER JOIN Users ON Passkeys.UserId = Users.Id
         WHERE Passkeys.Id=?;`, passkeyID)

const getSessionID = (async (challenge) => {
    let row = await get(`SELECT rowid, ChallengeExpiry
                         FROM Sessions
                         WHERE Challenge=?;`, challenge)
    if (row === undefined) return undefined
    return [row['rowid'], row['ChallengeExpiry']]
})

const getSession = (async (token) => {
    let row = await get(`SELECT Users.Id, Users.Username, Sessions.Expires
                         FROM Sessions
                         INNER JOIN Users ON Sessions.UserId = Users.Id
                         WHERE Token=?;`, token)
    if (row === undefined) return undefined
    return [row['Id'], row['Username'], row['Expires']]
})

const instateSession = (token, userID, expires, sessionID) =>
    run(`UPDATE Sessions
         SET Challenge=NULL, ChallengeExpiry=NULL, Token=?, UserId=?, Expires=?
         WHERE rowid=?`, token, userID, expires, sessionID)

const deleteSession = (token) =>
    run(`DELETE FROM Sessions WHERE Token=?`, token)

const instateOAuthToken = (tokenHash, friendlyName, clientID, parentToken,
    userID, permissions, expires) => run(`
    INSERT INTO Tokens (
        TokenHash,
        FriendlyName,
        ClientId,
        ParentToken,
        UserId,
        Permissions,
        Expires
    )
    VALUES (?, ?, ?, ?, ?, ?, ?);`, tokenHash, friendlyName, clientID,
    parentToken, userID, permissions, expires)

const getOAuthTokenInfo = (tokenHash) =>
    get(`SELECT Users.Id, Users.Username, Tokens.Permissions,
         Tokens.Expires
         FROM TOKENS
         INNER JOIN Users ON Tokens.UserId = Users.Id
         WHERE TokenHash=?;`, tokenHash)

const AUTHORIZATION_TYPE_TOKEN = 0
const AUTHORIZATION_TYPE_PASSKEY = 1

const instateOneTimeAuthorization = (tokenHash, type, userID, permissions) =>
    run(`INSERT INTO Authorizations (
            TokenHash,
            Type,
            UserId,
            Permissions)
         VALUES (?, ?, ?, ?);`, tokenHash, type, userID, permissions)

const lookupAuthorization = (tokenHash) =>
    get(`SELECT Type, UserId, Permissions, Expires
         FROM Authorizations
         WHERE TokenHash=?;`, tokenHash)

const deleteAuthorization = (tokenHash) =>
    run(`DELETE FROM Authorizations
         WHERE TokenHash=?;`, tokenHash)

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
    instateOneTimeAuthorization,
    lookupAuthorization,
    deleteAuthorization
}