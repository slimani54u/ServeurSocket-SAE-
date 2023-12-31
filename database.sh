#!/bin/bash

# Demander le nom d'utilisateur et le mot de passe MySQL pour la connexion root
echo "Entrez votre nom d'utilisateur MySQL root:"
read DB_USER

echo "Entrez votre mot de passe MySQL root:"
read -s DB_PASS

# Chemin du fichier SQL
SQL_FILE="ModeleRelationnel.sql"

# Commande pour importer le fichier SQL
mysql -u$DB_USER -p$DB_PASS < $SQL_FILE

echo "Importation terminée."

# Créer l'utilisateur toto et lui donner les droits d'accès
NEW_USER="toto"
NEW_PASS="toto"

# Commandes SQL pour créer l'utilisateur et lui donner les droits
mysql -u$DB_USER -p$DB_PASS -e "CREATE USER '$NEW_USER'@'%' IDENTIFIED BY '$NEW_PASS';"
mysql -u$DB_USER -p$DB_PASS -e "GRANT ALL PRIVILEGES ON *.* TO '$NEW_USER'@'%' WITH GRANT OPTION;"
mysql -u$DB_USER -p$DB_PASS -e "FLUSH PRIVILEGES;"

echo "Utilisateur 'toto' créé avec succès et tous les privilèges accordés."
