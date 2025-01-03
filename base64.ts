export const b64url = (val: string) => val.replace(/\+/g, '-').replace(/\//g, '_')
    .replace(/[^A-Za-z0-9-_]/g, '')

export const b64clean = (val: string) => {
    val = val.replace(/-/g, '+').replace(/_/g, '/')
        .replace(/[^A-Za-z0-9\+\/=]/g, '')
    for (var i = 0; i < Math.min(2, val.length % 4); i++) {
        val += '='
    }
    return val
}