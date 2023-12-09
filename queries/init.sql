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
    CreatedOn INT DEFAULT unixepoch(),
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
    TokenHash TEXT PRIMARY KEY,
    FriendlyName TEXT,
    ClientId INT,
    UserId INT NOT NULL,
    Permissions INT DEFAULT 0,
    CreatedOn INT DEFAULT unixepoch(),
    Expires INT NOT NULL
    FOREIGN KEY(UserId) REFERENCES Users(Id)
);

CREATE TABLE Authorizations (
    TokenHash TEXT PRIMARY KEY,
    Type INT DEFAULT 0,
    UserId INT NOT NULL,
    Permissions INT NOT NULL,
    Expires INT DEFAULT (unixepoch() + 600),
    FOREIGN KEY(UserId) REFERENCES Users(Id)
);