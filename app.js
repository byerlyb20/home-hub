require('dotenv').config()
const express = require('express')
const cookieParser = require('cookie-parser')
const net = require('net')
const db = require('./dbController')
const auth = require('./authController')

const app = express()

const SOCKET = process.env.GARAGE_SOCKET
const HOSTNAME = process.env.HOSTNAME
const PORT = process.env.PORT

db.connect('home.db')
auth.config(HOSTNAME)

app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(auth.auth)

app.use(express.static('web'))

app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`)
})

app.post('/auth/register/start', auth.registerStart)
app.post('/auth/register/finish', auth.registerFinish)
app.post('/auth/login/start', auth.loginStart)
app.post('/auth/login/finish', auth.loginFinish)
app.post('/auth/logout', auth.logout)

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
