import { smarthome, SmartHomeV1ExecuteResponseCommands } from "actions-on-google"
import { google } from "googleapis"
import { assertUserPermission, AuthorizationError, Permission } from "./permissions"
import { AuthenticatedRequest, smarthomeController } from "./app"

const app = smarthome()

const homegraphClient = google.homegraph({
    version: 'v1',
    auth: new google.auth.GoogleAuth({
        scopes: 'https://www.googleapis.com/auth/homegraph'
    })
})

const requestSyncForUser = (userId: string) => homegraphClient.devices.requestSync({
    requestBody: {
        agentUserId: userId,
        async: false
    }
})

app.onSync((body, headers, metadata) => {
    const request = metadata.express?.request as (AuthenticatedRequest | undefined)
    let user = request?.user
    if (!user) {
        throw new AuthorizationError()
    }
    assertUserPermission(user, Permission.AccountActor)
    // TODO Get devices for user
    return {
        requestId: body.requestId,
        payload: {
            agentUserId: String(user.id),
            devices: [{
                id: "123",
                type: "action.devices.types.GARAGE",
                traits: [
                    "action.devices.traits.OpenClose"
                ],
                name: {
                    name: "Right Door",
                    defaultNames: [],
                    nicknames: []
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
                    name: "Left Door",
                    defaultNames: [],
                    nicknames: []
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
    const request = metadata.express?.request as (AuthenticatedRequest | undefined)
    let user = request?.user
    if (!user) {
        throw new AuthorizationError()
    }
    assertUserPermission(user, Permission.AccountActor)
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

const BAY_IDS: {
    [key: string]: number
} = {
    '123': 0,
    '456': 1
}

app.onExecute(async (body, headers, metadata) => {
    const request = metadata.express?.request as (AuthenticatedRequest | undefined)
    let user = request?.user
    if (!user) {
        throw new AuthorizationError()
    }
    assertUserPermission(user, Permission.AccountActor)

    var commandsResponse: SmartHomeV1ExecuteResponseCommands[] = []

    let commandGroups = body.inputs[0].payload.commands
    for (const commandGroup of commandGroups) {
        let executions = commandGroup.execution
        let devices = commandGroup.devices
        for (const execution of executions) {
            console.log('Handling an execution %s', execution.command)
            switch (execution.command) {
                case 'action.devices.commands.OpenClose':
                    for (const device of devices) {
                        let bay = BAY_IDS[device.id] ?? 0
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