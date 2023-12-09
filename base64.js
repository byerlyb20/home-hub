const b64url = (val) => val.replace(/\+/g, '-').replace(/\//g, '_')
    .replace(/[^A-Za-z0-9-_]/g, '')

const clean = (val) => {
    val = val.replace(/-/g, '+').replace(/_/g, '/')
        .replace(/[^A-Za-z0-9\+\/=]/g, '')
    for (var i = 0; i < Math.min(2, val.length % 4); i++) {
        val += '='
    }
    return val
}

module.exports = {
    b64url,
    clean
}