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

app.use('/auth', auth.authRouter(HOSTNAME))

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
