require('dotenv').config()
const express = require('express')
const cookieParser = require('cookie-parser')
const Joi = require('joi')

const db = require('./dbController')
const auth = require('./authController')
const perm = require('./permissions')
const homegraph = require('./GoogleHomeGraphController')
const smarthome = require('./smarthomeController')

const app = express()

const PORT = process.env.PORT

db.connect('home.db')
smarthome.config(process.env.GARAGE_SOCKET)

// Error status codes are passed on by Express as the HTTP response status
Joi.ValidationError.prototype.statusCode = 400

// Wrap middleware to catch errors and pass them to next(); this is done
// automatically in Express 5.x
const errorWrapper = (middleware) => (req, res, next) =>
    Promise.resolve(middleware(req, res, next)).catch(next)

app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(auth.authState)

app.use(express.static('web'))

app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`)
})

app.use('/auth', auth.authRouter())

app.post('/api/v1/toggle/', async (req, res) => {
    perm.assertUserPermission(req.user, perm.PERMISSION_ACCOUNT_ACTOR)
    var bay = req.body.bay || 0
    smarthome.toggleGarage(bay).then(() => {
        res.status(200).end()
    }).catch((e) => {
        res.status(500).end()
    })
})

app.post('/fulfillment', homegraph.app)

app.get('/user', (req, res) => {
    res.json(req.user || {})
})

app.all('/request_homegraph_sync', async (req, res) => {
    perm.assertUserPermission(req.user, perm.PERMISSION_ACCOUNT_ACTOR)
    await homegraph.requestSyncForUser(req.user.id.toString())
    res.status(200).end()
})
