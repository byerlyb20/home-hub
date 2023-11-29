SELECT Users.Username, Passkeys.PublicKey
FROM Passkeys
INNER JOIN Users ON Passkeys.UserId = Users.Id
WHERE Passkeys.Id="";