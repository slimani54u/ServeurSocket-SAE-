#!/bin/bash

# Demander le nom d'utilisateur et le mot de passe MySQL pour la connexion root
echo "Entrez votre nom d'utilisateur MySQL root:"
read DB_USER

echo "Entrez votre mot de passe MySQL root:"
read -s DB_PASS

# Nom de la base de données
DB_NAME="serveur_discussion"

# Chemin du fichier SQL
SQL_FILE="ModeleRelationnel.sql"

# Créer la base de données
mysql -u$DB_USER -p$DB_PASS -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;"

# Importer le fichier SQL dans la base de données nouvellement créée
mysql -u$DB_USER -p$DB_PASS $DB_NAME < $SQL_FILE

echo "Base de données '$DB_NAME' créée et importation terminée."

# Créer l'utilisateur toto et lui donner les droits d'accès
NEW_USER="toto"
NEW_PASS="toto"

# Commandes SQL pour créer l'utilisateur et lui donner les droits
mysql -u$DB_USER -p$DB_PASS -e "CREATE USER '$NEW_USER'@'%' IDENTIFIED BY '$NEW_PASS';"
mysql -u$DB_USER -p$DB_PASS -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$NEW_USER'@'%' WITH GRANT OPTION;"
mysql -u$DB_USER -p$DB_PASS -e "FLUSH PRIVILEGES;"

echo "Utilisateur 'toto' créé avec succès et tous les privilèges accordés sur la base de données $DB_NAME."
