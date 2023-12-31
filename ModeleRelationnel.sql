
CREATE TABLE Authentification (
    ID INT PRIMARY KEY AUTO_INCREMENT,
    adresse_ip VARCHAR(15) NOT NULL,
    alias VARCHAR(50) UNIQUE NOT NULL,
    nom VARCHAR(50),
    prenom VARCHAR(50),
    password VARCHAR(255) NOT NULL,
    droit VARCHAR(50) DEFAULT '0',
    is_banned BOOLEAN DEFAULT FALSE,
    kick_expiration DATETIME DEFAULT NULL
);

CREATE TABLE Discussion (
    ID INT PRIMARY KEY AUTO_INCREMENT,
    alias VARCHAR(50),
    destination VARCHAR(50),
    conversation TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alias) REFERENCES Authentification(alias)
);

CREATE TABLE Status (
    ID INT PRIMARY KEY AUTO_INCREMENT,
    alias VARCHAR(50),
    status_connexion VARCHAR(20),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alias) REFERENCES Authentification(alias)
);

CREATE TABLE Salon (
    ID INT PRIMARY KEY AUTO_INCREMENT,
    nom VARCHAR(50),
    message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Droit_Salon (
    ID INT PRIMARY KEY AUTO_INCREMENT,
    alias VARCHAR(50),
    droits VARCHAR(50) DEFAULT '1,0,0,0,0',
    FOREIGN KEY (alias) REFERENCES Authentification(alias)
);

INSERT INTO Salon (nom, message) VALUES ('Général', 'Bienvenue dans le salon Général');
INSERT INTO Salon (nom, message) VALUES ('Blabla', 'Bienvenue dans le salon Blabla !');
INSERT INTO Salon (nom, message) VALUES ('Comptabilité', 'Bienvenue dans le salon Comptabilité !');
INSERT INTO Salon (nom, message) VALUES ('Informatique', 'Bienvenue dans le salon Informatique !');
INSERT INTO Salon (nom, message) VALUES ('Marketing', 'Bienvenue dans le salon Marketing !');
INSERT INTO Authentification (adresse_ip, alias, nom, prenom, password,droit) VALUES ('127.0.0.1', 'admin', 'admin', 'admin', 'admin', '1');
INSERT INTO Authentification (adresse_ip, alias, nom, prenom, password,droit) VALUES ('127.0.0.1', 'toto', 'toto', 'toto', 'toto', '0');
INSERT INTO Droit_Salon (alias, droits) VALUES ('admin', '1,1,1,1,1');
INSERT INTO Droit_Salon (alias) VALUES ('toto');
INSERT INTO Status (alias, status_connexion) VALUES ('admin', 'déconnecté');
INSERT INTO Status (alias, status_connexion) VALUES ('toto', 'déconnecté');

