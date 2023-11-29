async function register() {
    // Obtain a challenge from the server
    let startBody = {
        username: document.getElementById('inputUsername').value
    }
    const startResponse = await fetch("auth/register/start", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(startBody)
    })

    // Ask the authenticator to generate a new public/private key pair
    const credentialIssueArgs = await startResponse.json()
    // Recreate Uint8 primitive arrays from JSON
    credentialIssueArgs.publicKey.challenge = base64toab(credentialIssueArgs.publicKey.challenge)
    let userID = credentialIssueArgs.publicKey.user.id
    credentialIssueArgs.publicKey.user.id = new Int32Array([userID]).buffer
    let credential = await navigator.credentials.create(credentialIssueArgs)

    // Send the server the new public key and signed challenge
    let finishParams = {
        userID: userID,
        attestationObject: abtobase64(credential.response.attestationObject),
        keyID: credential.id,
        publicKey: abtobase64(credential.response.getPublicKey()),
        alg: credential.response.getPublicKeyAlgorithm()
    }
    console.log(JSON.stringify(finishParams))
    const finishResponse = await fetch("auth/register/finish", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(finishParams)
    })
}

async function login() {
    // Obtain a challenge from the server
    let startBody = {}
    const startResponse = await fetch("auth/login/start", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(startBody)
    })

    // Ask the authenticator to sign the challenge using an existing private key
    const credentialGetArgs = await startResponse.json()
    // Recreate Uint8 primitive arrays from JSON
    credentialGetArgs.publicKey.challenge = base64toab(credentialGetArgs.publicKey.challenge)
    let credential = await navigator.credentials.get(credentialGetArgs)

    let finishParams = {
        keyID: credential.id,
        signature: abtobase64(credential.response.signature),
        authenticatorData: abtobase64(credential.response.authenticatorData),
        clientDataJSON: abtobase64(credential.response.clientDataJSON)
    }
    const finishResponse = await fetch("auth/login/finish", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(finishParams)
    })
    console.log(await finishResponse.json())
}

async function logout() {
    await fetch("auth/logout", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        }
    })
}

function abtobase64(ab) {
    var binary = ''
    var bytes = new Uint8Array(ab)
    for (var i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary)
}

function base64toab(base64) {
    const binary = atob(base64)
    var buffer = new Uint8Array(binary.length)
    for (var i = 0; i < binary.length; i++) {
        buffer[i] = binary.charCodeAt(i)
    }
    return buffer
}
