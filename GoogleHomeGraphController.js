const { smarthome } = require('actions-on-google')
const perm = require('./permissions.js')

const app = smarthome()

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
                    "online": true
                },
                "456": {
                    "online": false
                }
            }
        }
    }
})

app.onExecute((body, headers, metadata) => {
    let user = metadata.express?.request?.user
    perm.assertUserPermission(user, perm.PERMISSION_ACCOUNT_ACTOR)

    let commandGroups = body.inputs[0].payload.commands
    for (let i = 0; i < commandGroups.length; i++) {
        let executions = commandGroups[i].execution
        for (let j = 0; j < executions.length; j++) {
            let execution = executions[j]
            console.log('Handling an execution %s', execution.command)
        }
    }

    // TODO Get devices for user
    return {
        requestId: body.requestId,
        payload: {
            commands: [{
                ids: ["123"],
                status: "SUCCESS",
                states: {
                    online: true,
                    openPercent: 100
                }
            }]
        }
    }
})

module.exports = app