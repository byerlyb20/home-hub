import { Authorization, Passkey, PrismaClient, Session, Token, User } from '@prisma/client'

const prisma = new PrismaClient()

type NewUser = Omit<User, 'id'|'permissions'> & Partial<Pick<User, 'permissions'>>
type NewPasskey = Omit<Passkey, 'createdOn'>
type NewToken = Omit<Token, 'permissions'|'createdOn'> & Partial<Pick<Token, 'permissions'>>
type NewSession = Omit<Session, 'userId'>

export enum AuthorizationType {
    Token = 0,
    Passkey = 1
}

export const createNewUser = (user: NewUser) =>
    prisma.user.create({ data: { ...user } })

export const getUserChallenge = async (id: number) => {
    const user = await prisma.user.findUnique({ where: { id }})
    return [user?.challenge, user?.challengeExpiry]
}

export const savePasskey = (passkey: NewPasskey) =>
    prisma.passkey.create({ data: { ...passkey } })

export const saveSession = (session: NewSession) =>
    prisma.session.create({ data: { ...session } })

export const getPasskey = (id: string) =>
    prisma.passkey.findUnique({
        where: { id },
        include: { user: true }
    })

export const getSessionExpiry = async (challenge: string) => {
    const session = await prisma.session.findUnique({ where: { challenge }})
    return session?.expires
}

export const getUnexpiredSession = (token: string) =>
    prisma.session.findUnique({
        where: {
            token,
            expires: {
                gt: new Date()
            }
        },
        include: { user: true }
    })

export const instateSessionWithUser = (challenge: string, userId: number) =>
    prisma.session.update({
        where: {
            challenge,
            challengeExpiry: {
                gt: new Date()
            }
        },
        data: {
            userId,
            challenge: null,
            challengeExpiry: null
        }
    })

export const deleteSession = (token: string) =>
    prisma.session.delete({ where: { token } })

export const saveOAuthToken = (token: NewToken) =>
    prisma.token.create({ data: { ...token } })

export const getOAuthToken = (tokenHash: string) =>
    prisma.token.findUnique({
        where: { tokenHash },
        include: { user: true }
    })

export const saveAuthorization = (authorization: Authorization) =>
    prisma.authorization.create({ data: { ...authorization } })

export const getAuthorization = (tokenHash: string) =>
    prisma.authorization.findUnique({ where: { tokenHash } })

export const deleteAuthorization = (tokenHash: string) =>
    prisma.authorization.delete({ where: { tokenHash } })