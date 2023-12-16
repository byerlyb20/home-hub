const { smarthome } = require('actions-on-google')
const { google } = require('googleapis')
const perm = require('./permissions')
const smarthomeController = require('./smarthomeController')

const app = smarthome()

const homegraphClient = google.homegraph({
    version: 'v1',
    auth: new google.auth.GoogleAuth({
        scopes: 'https://www.googleapis.com/auth/homegraph'
    })
})

const requestSyncForUser = (userID) => homegraphClient.devices.requestSync({
    requestBody: {
        agentUserId: userID,
        async: false
    }
})

app.onSync((body, headers, metadata) => {
    let user = metadata.express?.request?.user
    perm.assertUserPermission(user, perm.PERMISSION_ACCOUNT_ACTOR)
    // TODO Get devices for user
    return {
        requestId: body.requestId,
        payload: {
            agentUserId: user.id,
            devices: [{
                id: "123",
                type: "action.devices.types.GARAGE",
                traits: [
                    "action.devices.traits.OpenClose"
                ],
                name: {
                    name: "Right Door"
                },
                willReportState: false,
                roomHint: "garage",
                deviceInfo: {
                    manufacturer: "byerly-family",
                    model: "garage1234",
                    hwVersion: "1.0",
                    swVersion: "1.0"
                },
                attributes: {
                    discreteOnlyOpenClose: true,
                    commandOnlyOpenClose: true
                }
            },
            {
                id: "456",
                type: "action.devices.types.GARAGE",
                traits: [
                    "action.devices.traits.OpenClose"
                ],
                name: {
                    name: "Left Door"
                },
                willReportState: false,
                roomHint: "garage",
                deviceInfo: {
                    manufacturer: "byerly-family",
                    model: "garage1234",
                    hwVersion: "1.0",
                    swVersion: "1.0"
                },
                attributes: {
                    discreteOnlyOpenClose: true,
                    commandOnlyOpenClose: true
                }
            }]
        }
    }
})

app.onQuery((body, headers, metadata) => {
    let user = metadata.express?.request?.user
    perm.assertUserPermission(user, perm.PERMISSION_ACCOUNT_ACTOR)
    // TODO Get devices for user
    return {
        requestId: body.requestId,
        payload: {
            devices: {
                "123": {
                    online: true,
                    status: 'SUCCESS',
                    openPercent: 0
                },
                "456": {
                    online: true,
                    status: 'SUCCESS',
                    openPercent: 0
                }
            }
        }
    }
})

const BAY_IDS = {
    '123': 0,
    '456': 1
}

app.onExecute(async (body, headers, metadata) => {
    let user = metadata.express?.request?.user
    perm.assertUserPermission(user, perm.PERMISSION_ACCOUNT_ACTOR)

    var commandsResponse = []

    let commandGroups = body.inputs[0].payload.commands
    for (commandGroup of commandGroups) {
        let executions = commandGroup.execution
        let devices = commandGroup.devices
        for (execution of executions) {
            console.log('Handling an execution %s', execution.command)
            switch (execution.command) {
                case 'action.devices.commands.OpenClose':
                    for (device of devices) {
                        let bay = BAY_IDS[device.id]
                        await smarthomeController.toggleGarage(bay).then(() => {
                            commandsResponse.push({
                                ids: [device.id],
                                status: "SUCCESS",
                                states: {
                                    online: true
                                }
                            })
                        }).catch((e) => {
                            commandsResponse.push({
                                ids: [device.id],
                                status: "ERROR"
                            })
                        })
                    }
            }
        }
    }

    // TODO Get devices for user
    return {
        requestId: body.requestId,
        payload: {
            commands: commandsResponse
        }
    }
})

module.exports = {
    app,
    requestSyncForUser
}