require('dotenv').config()
const express = require('express')
const cookieParser = require('cookie-parser')
const net = require('net')
const Joi = require('joi')

const db = require('./dbController')
const auth = require('./authController')

const app = express()

const SOCKET = process.env.GARAGE_SOCKET
const HOSTNAME = process.env.HOSTNAME
const PORT = process.env.PORT

db.connect('home.db')
auth.config(HOSTNAME)

// Error status codes are passed on by Express as the HTTP response status
Joi.ValidationError.prototype.statusCode = 400

// Wrap middleware to catch errors and pass them to next(); this is done
// automatically in Express 5.x
const errorWrapper = (middleware) => (req, res, next) =>
    Promise.resolve(middleware(req, res, next)).catch(next)

app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(errorWrapper(auth.auth))

app.use(express.static('web'))

app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`)
})

app.post('/auth/register/start', errorWrapper(auth.registerStart))
app.post('/auth/register/finish', errorWrapper(auth.registerFinish))
app.post('/auth/login/start', errorWrapper(auth.loginStart))
app.post('/auth/login/finish', errorWrapper(auth.loginFinish))
app.post('/auth/logout', errorWrapper(auth.logout))
app.post('/auth/tokenExchange', errorWrapper(auth.tokenExchange))
app.all('/auth/login/landing', errorWrapper(auth.landing))

app.post('/api/v1/toggle/', (req, res) => {
    var bay = req.body.bay || 0
    var client = net.createConnection(SOCKET)
        .on('connect', () => {
            client.write(new Uint8Array([0, bay]))
            client.end()
        })
    res.status(200).end()
})

app.get('/user', (req, res) => {
    res.json(req.user)
})
