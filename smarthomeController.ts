import net from 'net'

export enum Bay {
    Bay1 = 0,
    Bay2 = 1
}

export class SmarthomeController {
    private garageSocket: string

    public constructor(garageSocket: string) {
        this.garageSocket = garageSocket
    }

    public toggleGarage(bay: Bay) {
        return new Promise<void>((resolve, reject) => {
            var client = net.createConnection(this.garageSocket)
                .on('connect', () => {
                    client.write(new Uint8Array([0, bay]))
                    client.end()
                    resolve()
                }).on('error', (e: Error) => {
                    reject(e)
                })
        })
    }
}
