require('dotenv').config()
import express, { NextFunction, Request, Response } from 'express'
import { User } from './models'
const cookieParser = require('cookie-parser')
const Joi = require('joi')

import { authState, authRouter } from './authController'
import { assertUserPermission, Permission } from './permissions'
import { SmarthomeController } from './smarthomeController'
const homegraph = require('./GoogleHomeGraphController')

type MiddlewareFunction = (req: Request, res: Response, next: NextFunction) => void
export type AuthenticatedRequest = Request & { user: (User | null | undefined) }

const app = express()
export const smarthomeController = new SmarthomeController(process.env.GARAGE_SOCKET ?? "")

const PORT = process.env.PORT

// Error status codes are passed on by Express as the HTTP response status
Joi.ValidationError.prototype.statusCode = 400

// Wrap middleware to catch errors and pass them to next(); this is done
// automatically in Express 5.x
const errorWrapper = (middleware: MiddlewareFunction) => (req: Request, res: Response, next: NextFunction) =>
    Promise.resolve(middleware(req, res, next)).catch(next)

app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(authState)

app.use(express.static('web'))

const server = app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`)
})

app.use('/auth', authRouter())

app.post('/api/v1/toggle/', async (req: Request, res: Response) => {
    assertUserPermission((req as AuthenticatedRequest).user, Permission.AccountActor)
    var bay = req.body.bay || 0
    smarthomeController.toggleGarage(bay).then(() => {
        res.status(200).end()
    }).catch((e: Error) => {
        res.status(500).end()
    })
})

app.post('/fulfillment', homegraph.app)

app.get('/user', (req, res) => {
    res.json((req as AuthenticatedRequest).user ?? {})
})

app.all('/request_homegraph_sync', async (req, res) => {
    const authReq = req as AuthenticatedRequest
    const user = assertUserPermission(authReq.user, Permission.AccountActor)
    await homegraph.requestSyncForUser(user.id.toString())
    res.status(200).end()
})

process.on('SIGTERM', () => {
    server.close(() => {
        console.log('Server closed')
    })
})
