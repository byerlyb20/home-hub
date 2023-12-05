async function updateUserDetail() {
    const userInfo = await user()
    if (userInfo !== undefined) {
        document.getElementById('activeSessionUsernameDetail').innerText = userInfo.username
        document.getElementById('activeSessionUserIDDetail').innerText = userInfo.id
    }
}

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