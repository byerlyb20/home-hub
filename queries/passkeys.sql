SELECT Users.Id, Users.Username, Passkeys.Id, Passkeys.PublicKey
FROM Passkeys
INNER JOIN Users ON Passkeys.UserId = Users.Id;