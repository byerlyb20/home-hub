const net = require('net')

let GARAGE_SOCKET

function config(garageSocket) {
    GARAGE_SOCKET = garageSocket
}

const toggleGarage = (bay) => new Promise((resolve, reject) => {
    var client = net.createConnection(GARAGE_SOCKET)
        .on('connect', () => {
            client.write(new Uint8Array([0, bay]))
            client.end()
            resolve()
        }).on('error', (e) => {
            reject(e)
        })
})

module.exports = {
    config,
    toggleGarage
}
