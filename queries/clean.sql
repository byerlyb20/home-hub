DELETE FROM Sessions
WHERE (Token IS NULL AND ChallengeExpiry<unixepoch()) OR (Expires<unixepoch());

DELETE FROM Authorizations
WHERE Expires<unixepoch();

DELETE FROM Tokens
WHERE Expires<unixepoch();