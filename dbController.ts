import { Authorization, Passkey, PrismaClient, Session, Token, User } from '@prisma/client'

const prisma = new PrismaClient()

type NewUser = Omit<User, 'permissions'> & Partial<Pick<User, 'permissions'>>
type NewPasskey = Omit<Passkey, 'createdOn'>
type NewToken = Omit<Token, 'permissions' | 'createdOn'> & Partial<Pick<Token, 'permissions'>>

export const createNewUser = (user: NewUser) =>
    prisma.user.create({ data: { ...user } })

export const getUserChallenge = async (id: number) => {
    const user = await prisma.user.findUnique({ where: { id }})
    return [user?.challenge, user?.challengeExpiry]
}

export const savePasskey = (passkey: NewPasskey) =>
    prisma.passkey.create({ data: { ...passkey } })

export const saveSession = (session: Session) =>
    prisma.session.create({ data: { ...session } })

export const getPasskey = (id: string) => prisma.passkey.findUnique({ where: { id }})

export const getSessionExpiry = async (challenge: string) => {
    const session = await prisma.session.findFirst({ where: { challenge }})
    return session?.expires
}

export const getSession = (token: string) =>
    prisma.session.findUnique({ where: { token } })

export const deleteSession = (token: string) =>
    prisma.session.delete({ where: { token } })

export const saveOAuthToken = (token: NewToken) =>
    prisma.token.create({ data: { ...token } })

export const getOAuthToken = (tokenHash: string) =>
    prisma.token.findUnique({ where: { tokenHash } })

export const saveAuthorization = (authorization: Authorization) =>
    prisma.authorization.create({ data: { ...authorization } })

export const getAuthorization = (tokenHash: string) =>
    prisma.authorization.findUnique({ where: { tokenHash } })

export const deleteAuthorization = (tokenHash: string) =>
    prisma.authorization.delete({ where: { tokenHash } })