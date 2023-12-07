document.addEventListener("DOMContentLoaded", async function(event) {
    const loggedIn = (await user()) || {};
    if (loggedIn.id !== undefined) {
        document.getElementById("clientDetail").innerText = "Google"
        document.getElementById("usernameDetail").innerText = loggedIn.username
        document.getElementById("parentContainer").hidden = false
    }
})

function deny() {
    
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