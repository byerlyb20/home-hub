DELETE FROM Sessions
WHERE Token=NULL
AND ChallengeExpiry<unixepoch();

DELETE FROM Sessions
WHERE Expires<unixepoch();