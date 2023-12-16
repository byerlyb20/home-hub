import { register, logout, user, createAPIToken } from "./auth.js"

document.addEventListener("DOMContentLoaded", async function(event) {
    document.getElementById('registerButton').addEventListener('click', async function(event) {
        let username = document.getElementById('inputUsername').value
        await register(username)
    })
    document.getElementById('tokenButton').addEventListener('click', apiTokenFormGenerate)
})

async function apiTokenFormGenerate() {
    const friendlyName = document.getElementById('inputAPITokenFriendlyName').value
    const token = await createAPIToken(friendlyName)
    if (token !== undefined) {
        document.getElementById('apiTokenDetail').innerText = token.token
        const expiry = new Date(token.expires * 1000)
        document.getElementById('apiTokenExpiresDetail').innerText = expiry.toDateString()
    }
}

updateUserDetail()