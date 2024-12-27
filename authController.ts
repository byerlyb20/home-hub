import express, { NextFunction, Request, Response } from 'express'
const subtle = globalThis.crypto.subtle
import Joi from 'joi'
import { AuthenticatedRequest } from './app'
import { assertUserPermission, Permission, Permissions } from './permissions'

const db = require('./dbController')
const base64 = require('./base64')
const perm = require('./permissions')

const SESSION_COOKIE_NAME = 'sessionToken'
const APP_DISPLAY_NAME = 'Home Hub'
const HOSTNAME = process.env.HOSTNAME

const CLIENT_ID_SELF = 0
const CLIENT_ID_GOOGLE = 1

type MiddlewareFunction = (req: Request, res: Response, next: NextFunction) => void

export const authRouter = () => {
    // Setting the hostname globally is probably poor design; look for a better
    // way to pass in configuration variables
    const router = express.Router()

    if (process.env.ENABLE_REGISTRATION) {
        router.post('/register/start', registerStart)
        router.post('/register/finish', registerFinish)
    }

    router.post('/login/start', loginStart)
    router.post('/login/finish', loginFinish)

    router.post('/logout', logout)

    router.post('/oauth/tokenExchange', tokenExchange)
    router.post('/oauth/authorization', oauthAuthorization)

    return router
}

const sessionTokenCookieSchema = Joi.string().base64()
const authorizationHeaderSchema = Joi.string().pattern(/Bearer [A-Za-z0-9+\/=]+$/)
const authorizationCodeSchema = Joi.string()
export const authState: MiddlewareFunction = async (req, res, next) => {
    let authReq = req as AuthenticatedRequest
    let sessionToken = req.cookies[SESSION_COOKIE_NAME]
    let oauthToken = req.headers.authorization
    Joi.assert(sessionToken, sessionTokenCookieSchema)
    Joi.assert(oauthToken, authorizationHeaderSchema)

    if (sessionToken !== undefined) {
        const [userID, username, expires] =
            await db.getSession(sessionToken) || []
        if (expires !== undefined && now() <= expires) {
            authReq.user = {
                id: userID,
                username: username,
                permissions: perm.PERMISSIONS_USER
            }
        } else {
            res.clearCookie(SESSION_COOKIE_NAME)
        }
    } else if (oauthToken !== undefined) {
        const oauthTokenHash = await base64Hash(oauthToken.substring(7))
        const { Id, Username, Permissions, Expires } =
            await db.getOAuthTokenInfo(oauthTokenHash) || {}
        if (Expires !== undefined && now() <= Expires) {
            authReq.user = {
                id: Id,
                username: Username,
                permissions: Permissions
            }
        }
    }
    next()
}

const registerStartSchema = Joi.object({
    username: Joi.string().required().alphanum().min(5).max(20)
})
const registerStart: MiddlewareFunction = async (req, res, next) => {
    Joi.assert(req.body, registerStartSchema)
    let username = req.body.username
    let [challenge, challengeExpiry] = generateChallenge()
    
    // TODO: Handle username conflicts gracefully
    let userID = await db.createNewUser(username, challenge, challengeExpiry)

    // Structured per https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create#publickey_object_structure
    let credentialIssueArgs = {
        publicKey: {
            challenge: challenge,
            rp: { id: HOSTNAME, name: APP_DISPLAY_NAME },
            user: {
                id: userID,
                name: username,
                displayName: username
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }]
        }
    }
    res.json(credentialIssueArgs)
}

const registerFinishSchema = Joi.object({
    attestationObject: Joi.string().required().base64(),
    userID: Joi.number().required().integer(),
    keyID: Joi.string().required().base64({ paddingRequired: false, urlSafe: true }),
    publicKey: Joi.string().required().base64(),
    alg: Joi.number().required().integer()
})
const registerFinish: MiddlewareFunction = async (req, res, next) => {
    Joi.assert(req.body, registerFinishSchema)
    let attestationObject = base64toab(req.body.attestationObject)

    // TODO: Check that challenge is unexpired and correct
    let [challenge, challengeExpiry] = await db.getUserChallenge(req.body.userID) || []

    await db.savePasskey(req.body.keyID, req.body.userID,
        req.body.publicKey)

    res.json({}).end()
}

const loginStart: MiddlewareFunction = async (req, res, next) => {
    let [challenge, challengeExpiry] = generateChallenge()
    
    await db.saveSessionChallenge(challenge, challengeExpiry)
    
    // Structured per https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get#publickey_object_structure
    let credentialGetArgs = {
        publicKey: {
            challenge: challenge,
            rp: HOSTNAME
        }
    }
    res.json(credentialGetArgs)
}

const loginFinishSchema = Joi.object({
    keyID: Joi.string().required().base64({ paddingRequired: false, urlSafe: true }),
    signature: Joi.string().required().base64(),
    authenticatorData: Joi.string().required().base64(),
    clientDataJSON: Joi.string().required().base64()
})
const loginFinish: MiddlewareFunction = async (req, res, next) => {
    Joi.assert(req.body, loginFinishSchema)
    // Lookup credential
    // { Username, UserId, PublicKey }
    const credential = await db.getPasskey(req.body.keyID)
    if (credential === undefined) {
        console.log('Unrecognized credential ID')
        res.status(401).end()
        return
    }

    // Verify credential
    const rawSignature = derToRaw(base64toab(req.body.signature))
    const [challenge, signatureContents] =
        await calculateSignatureContents(req.body.authenticatorData,
            req.body.clientDataJSON)

    const verified = await verify(credential.PublicKey, rawSignature,
        signatureContents)
    if (!verified) {
        console.log('Signature could not be verified with known public key')
        res.status(401).end()
        return
    }
    
    // Lookup pending session entry (ensures that the challenge is valid)
    const [sessionID, challengeExpiry] = await db.getSessionID(challenge) || []
    if (sessionID === undefined) {
        console.log('Invalid challenge')
        res.status(401).end()
        return
    }
    if (now() > challengeExpiry) {
        console.log('Expired challenge')
        res.status(401).end()
        return
    }

    // Issue a session token
    const [token, expires] = generateSessionToken()
    await db.instateSession(token, credential.UserId, expires, sessionID)

    res.cookie(SESSION_COOKIE_NAME, token, {
        expires: new Date(expires * 1000),
        httpOnly: true
    }).json({
        username: credential.Username,
        expires: expires
    })
}

const logout: MiddlewareFunction = async (req, res, next) => {
    let sessionToken = req.cookies[SESSION_COOKIE_NAME]
    if (sessionToken !== undefined) {
        await db.deleteSession(sessionToken)
        res.clearCookie(SESSION_COOKIE_NAME)
    }
    res.json({})
}

const tokenQuerySchema = Joi.object({
        name: Joi.string().alphanum().max(30),
        grant_type: Joi.string().valid('authorization_code', 'refresh_token'),
        client_id: Joi.number().integer(),
        client_secret: Joi.string()
    })
    .xor('name', 'grant_type')
    .and('grant_type', 'client_id', 'client_secret')
    .when(Joi.object({ grant_type: 'authorization_code' }).unknown(), {
        then: Joi.object({
            code: Joi.string().base64().required(),
            redirect_uri: Joi.string().uri().required()
        })
    })
    .when(Joi.object({ grant_type: 'refresh_token' }).unknown(), {
        then: Joi.object({
            refresh_token: Joi.string().base64({ urlSafe: true, paddingRequired: false }).required()
        })
    })
const tokenExchange: MiddlewareFunction = async (req, res, next) => {
    try {
        Joi.assert(req.body, tokenQuerySchema)
        if (req.body.name === undefined) {
            let refreshTokenHash
            let urlSafeRefreshToken = ''

            if (req.body.grant_type == 'authorization_code') {
                const tokenHash = await base64Hash(req.body.code)
                // { Type, UserId, Permissions, Expires }
                const authorization = await db.lookupAuthorization(tokenHash)
                await db.deleteAuthorization(tokenHash)
        
                if (authorization === undefined || now() >= authorization.Expires) {
                    throw new perm.AuthorizationError()
                }
                perm.assertPermission(authorization.Permissions,
                    perm.PERMISSION_ISSUE_REFRESH_TOKEN)

                const refreshToken = await createRefreshToken(authorization.UserId,
                    req.body.client_id)
                refreshTokenHash = refreshToken.hash
                urlSafeRefreshToken = base64.b64url(refreshToken.token)
            } else if (req.body.grant_type == 'refresh_token') {
                refreshTokenHash = await base64Hash(req.body.refresh_token)
            }

            const refreshToken = await db.getOAuthTokenInfo(refreshTokenHash)

            if (refreshToken === undefined || now() >= refreshToken.Expires) {
                throw new perm.AuthorizationError()
            }
            perm.assertPermission(refreshToken.Permissions, perm.PERMISSION_ISSUE_ACCESS_TOKEN)

            const accessToken = await createAccessToken(refreshToken.Id,
                req.body.client_id, refreshToken.TokenHash)

            res.json({
                token_type: 'Bearer',
                refresh_token: urlSafeRefreshToken,
                access_token: accessToken.token,
                expires_in: 86400
            })
        } else {
            const user = assertUserPermission((req as AuthenticatedRequest).user, Permission.IssueAccessToken)
            const token = await createAPIToken(user.id, '')
            res.json({
                token: token.token,
                name: req.body.name,
                expires: token.expiry
            })
        }
    } catch (e) {
        if (e instanceof perm.AuthorizationError) {
            res.status(400).json({
                error: "invalid_grant"
            })
        } else {
            throw e
        }
    }
}

const oauthAuthorizationSchema = Joi.object({
    clientID: Joi.number().integer(),
    scope: Joi.string()
})
const oauthAuthorization: MiddlewareFunction = async (req, res) => {
    Joi.assert(req.body, oauthAuthorizationSchema)
    const user = assertUserPermission((req as AuthenticatedRequest).user, Permission.AccountActor)
    const token = await generateAuthorizationToken()
    await db.instateOneTimeAuthorization(token.hash,
        db.AUTHORIZATION_TYPE_TOKEN,
        user.id,
        perm.PERMISSIONS_OAUTH_AUTHORIZATION)
    
    res.json({
        code: token.token
    })
}

const clientDataJSONSchema = Joi.object({
    type: Joi.any().required().valid('webauthn.get'),
    challenge: Joi.string().required().base64({ paddingRequired: false, urlSafe: true }),
    origin: Joi.string().required()
})
async function calculateSignatureContents(authenticatorData: string, clientDataJSONBase64: string) {
    const authenticatorDataBuffer = Buffer.from(authenticatorData, 'base64')

    const clientDataBuffer = base64toab(clientDataJSONBase64)
    const clientDataHash = await subtle.digest('SHA-256', clientDataBuffer)
    const clientDataJSON = JSON.parse(clientDataBuffer.toString('utf8'))
    Joi.assert(clientDataJSON, clientDataJSONSchema)
    const challenge = base64.clean(clientDataJSON.challenge)

    const signatureContents = appendBuffer(authenticatorDataBuffer,
        clientDataHash)
    
    return [challenge, signatureContents]
}

function importKey(publicKeyBase64: string) {
    const keyImportParams = {
        name: 'ECDSA',
        namedCurve: 'P-256'
    }
    return subtle.importKey('spki', base64toab(publicKeyBase64),
        keyImportParams, false, ['verify'])
}

async function verify(publicKey: string, signature: BufferSource, signatureContents: BufferSource) {
    const key = await importKey(publicKey)
    const algorithm = {
        name: 'ECDSA',
        hash: 'SHA-256'
    }
    return subtle.verify(algorithm, key, signature, signatureContents)
}

const generateChallenge = () => generateToken(32, 600)
const generateSessionToken = () => generateToken(64, 86400)
const generateAuthorizationToken = () => generateHashedToken(32, 600)

const createAPIToken = (user: number, name: string) =>
    createToken(perm.PERMISSIONS_API_TOKEN, user, name, CLIENT_ID_SELF, null, 64,
        31536000)
const createRefreshToken = (user: number, clientID: number) =>
    createToken(perm.PERMISSIONS_REFRESH_TOKEN, user, '', clientID, null, 64,
        31536000)
const createAccessToken = (user: number, clientID: number, parentTokenHash: string) =>
    createToken(perm.PERMISSIONS_ACCESS_TOKEN, user, '', clientID, parentTokenHash,
        64, 86400)

async function createToken(allowedPermissions: Permissions, userID: number, name: string, clientID: number,
    parentTokenHash: string | null, length: number, validFor: number) {
    const token = await generateHashedToken(length, validFor)
    await db.instateOAuthToken(token.hash, name, clientID, parentTokenHash,
        userID, allowedPermissions, token.expiry)
    return token
}

function now() {
    return Math.round(Date.now() / 1000)
}

function generateToken(len: number, validDuration: number): [string, number] {
    let token = globalThis.crypto.getRandomValues(new Uint8Array(len))
    let expires = now() + validDuration
    return [abtobase64(token), expires]
}

async function generateHashedToken(len: number, validDuration: number) {
    let token = globalThis.crypto.getRandomValues(new Uint8Array(len))
    let tokenHash = await subtle.digest('SHA-256', token)
    return {
        token: abtobase64(token),
        hash: abtobase64(tokenHash),
        expiry: now() + validDuration
    }
}

function abtobase64(ab: ArrayBuffer) {
    return Buffer.from(ab).toString('base64')
}

function base64toab(base64: string) {
    return Buffer.from(base64, 'base64')
}

async function base64Hash(base64: string) {
    let raw = base64toab(base64)
    let hashRaw = await subtle.digest('SHA-256', raw)
    return abtobase64(hashRaw)
}

function appendBuffer(a: Buffer | ArrayBuffer, b: Buffer | ArrayBuffer) {
    // Required because arguments may be arrays or array buffers, not instances
    // of Buffer
    const buffer1 = Buffer.from(a)
    const buffer2 = Buffer.from(b)

    var buffer = Buffer.alloc(buffer1.byteLength + buffer2.byteLength)
    buffer1.copy(buffer, 0)
    buffer2.copy(buffer, buffer1.byteLength)
    return buffer;
}

// Taken from https://github.com/webauthn-open-source/fido2-lib/blob/master/lib/toolbox.js
// Will zero pad short arrays up to an expected length
function extractBigNum(fullArray: Buffer, start: number, end: number, expectedLength: number) {
	let num = fullArray.subarray(start, end);
	if (num.length !== expectedLength){
		return Array(expectedLength).fill(0).concat(...num).slice(num.length);
	}
	return num;
}

// Taken from https://github.com/webauthn-open-source/fido2-lib/blob/master/lib/toolbox.js
function derToRaw(signature: Buffer) {
	const rStart = 4;
	const rEnd = rStart + signature[3];
	const sStart = rEnd + 2;
	return new Uint8Array([
		...extractBigNum(signature, rStart, rEnd, 32),
		...extractBigNum(signature, sStart, signature.length, 32),
	]);
}