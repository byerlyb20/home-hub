import { login, logout, user, getOAuthAuthCode } from "./auth.js"

const PAGES = [
    document.getElementById("loginContainer"),
    document.getElementById("oauthContainer"),
    document.getElementById("welcomeContainer")
]

const [ PAGE_LOGIN, PAGE_OAUTH, PAGE_WELCOME ] = [0, 1, 2]

function showPage(num) {
    for (let i = 0; i < PAGES.length; i++) {
        PAGES[i].hidden = i != num
    }
}

document.addEventListener("DOMContentLoaded", async function(event) {
    document.getElementById('loginButton').addEventListener('click', async function(event) {
        await login()
        await checkLogin()
    })
    document.getElementById('oauthAcceptButton').addEventListener('click', accept)
    document.getElementById('logoutButton').addEventListener('click', async function(event) {
        await logout()
        await checkLogin()
    })
    await checkLogin()
})

async function checkLogin() {
    const currentUser = (await user()) || {}
    if (currentUser.id === undefined) {
        showPage(PAGE_LOGIN)
    } else {
        whenLoggedIn()
    }
}

function whenLoggedIn(currentUser) {
    const urlParams = new URLSearchParams(window.location.search)
    const responseType = urlParams.get('response_type')
    const clientID = parseInt(urlParams.get('client_id'))
    const redirectURI = urlParams.get('redirect_uri')

    if (responseType === 'code') {
        // Handle OAuth request
        document.getElementById("clientDetail").innerText = "Client ID " + clientID
        document.getElementById("usernameDetail").innerText = currentUser.username
        showPage(PAGE_OAUTH)
    } else if (redirectURI !== null) {
        // Handle login redirect request
        window.location.replace(redirectURI)
    } else {
        showPage(PAGE_WELCOME)
    }
}

async function accept() {
    const urlParams = new URLSearchParams(window.location.search)
    const clientID = parseInt(urlParams.get('client_id'))
    const redirectURI = urlParams.get('redirect_uri')
    const state = urlParams.get('state')
    const scope = urlParams.get('scope')

    const authCodeResponse = await getOAuthAuthCode(clientID, scope)

    if (authCodeResponse.code !== undefined) {
        const redirectURL = new URL(redirectURI)
        redirectURL.searchParams.set('state', state)
        redirectURL.searchParams.set('code', authCodeResponse.code)
        window.location.replace(redirectURL.toString())
    }
}