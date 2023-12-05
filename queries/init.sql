CREATE TABLE Users (
    Id INTEGER PRIMARY KEY,
    Username TEXT UNIQUE NOT NULL,
    Permissions INT DEFAULT 0,
    Challenge TEXT,
    ChallengeExpiry INT
);

CREATE TABLE Passkeys (
    Id TEXT PRIMARY KEY,
    UserId INT NOT NULL,
    PublicKey TEXT NOT NULL,
    CreatedOn TEXT,
    FOREIGN KEY(UserId) REFERENCES Users(Id)
);

CREATE TABLE Sessions (
    Token TEXT,
    UserId INT,
    Expires INT,
    Challenge TEXT,
    ChallengeExpiry INT,
    FOREIGN KEY(UserId) REFERENCES Users(Id)
);

CREATE TABLE Tokens (
    TokenHash TEXT,
    FriendlyName TEXT,
    ClientId INT,
    UserId INT,
    Permissions INT DEFAULT 0,
    CreatedOn INT,
    Expires INT,
    FOREIGN KEY(UserId) REFERENCES Users(Id)
);