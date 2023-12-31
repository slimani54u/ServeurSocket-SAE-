from datetime import datetime, timedelta
import socket
import sys
import threading
import time

from sqlalchemy import create_engine, MetaData, Table, select
from sqlalchemy.orm import sessionmaker, declarative_base

Base = declarative_base()

metadata = MetaData()

# Initialisation de la base de données (MySQL pour cet exemple)
db_connection_string = 'mysql+mysqlconnector://toto:toto@%:3306/serveur_discussion'
engine = create_engine(db_connection_string)
metadata.create_all(engine)

class Authentification(Base):
    __table__ = Table('Authentification', metadata, autoload_with=engine)

class Status(Base):
    __table__ = Table('Status', metadata, autoload_with=engine)

class Salon(Base):
    __table__ = Table('Salon', metadata, autoload_with=engine)

class Discussion(Base):
    __table__ = Table('Discussion', metadata, autoload_with=engine)

class Droit_Salon(Base):
    __table__ = Table('Droit_salon', metadata, autoload_with=engine)

class Server:
    def __init__(self, host, port):
        self.message_salon_input = None
        self.salon_box = None
        self.host = host
        self.port = port
        self.clients = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        print(f"Serveur en attente sur {self.host}:{self.port}")

    def start(self):
        self.server_socket.settimeout(1)  # Définir un timeout

        shutdown_thread = threading.Thread(target=self.listen_for_shutdown_command)
        shutdown_thread.start()

        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"Connexion acceptée de {client_address}")
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
                client_handler.start()
            except socket.timeout:
                continue  # Ignorer le timeout et continuer la boucle
            except Exception as e:
                print(f"Erreur inattendue: {e}")

        self.shutdown_server()

    def listen_for_shutdown_command(self):
        while True:
            command = input("Entrez une commande: ")
            args = command.split()

            if len(args) == 0:
                continue

            command_type = args[0].lower()
            if command_type == "kill":
                print("Arrêt du serveur en cours...")
                self.running = False
                break
            elif command_type == "ban" and len(args) == 2:
                self.ban_user(args[1])
                print(f"Utilisateur {args[1]} banni.")
            elif command_type == "kick" and len(args) == 3:
                try:
                    duration = int(args[2])
                    self.kick_user(args[1], duration)
                    print(f"Utilisateur {args[1]} expulsé pour {duration} heures.")
                except ValueError:
                    print("Durée invalide pour l'expulsion.")
            elif command_type == "unban" and len(args) == 2:
                self.unban_user(args[1])
                print(f"Utilisateur {args[1]} débanni.")
            elif command_type == "unkick" and len(args) == 2:
                self.unkick_user(args[1])
                print(f"Expulsion de l'utilisateur {args[1]} annulée.")

    def unkick_user(self, identifier):
        session = sessionmaker(bind=engine)()
        user = session.query(Authentification).filter(
            (Authentification.alias == identifier) | (Authentification.adresse_ip == identifier)).first()
        if user:
            user.kick_expiration = None
            session.commit()
            print(f"L'utilisateur {identifier} a été réintégré (unkicked).")
        else:
            print(f"Aucun utilisateur trouvé avec l'identifiant {identifier}")
        session.close()

    def unban_user(self, identifier):
        session = sessionmaker(bind=engine)()
        user = session.query(Authentification).filter(
            (Authentification.alias == identifier) | (Authentification.adresse_ip == identifier)).first()
        if user:
            user.is_banned = False
            session.commit()
            print(f"L'utilisateur {identifier} a été débanni.")
        else:
            print(f"Aucun utilisateur trouvé avec l'identifiant {identifier}")
        session.close()

    def ban_user(self, identifier):
        session = sessionmaker(bind=engine)()
        user = session.query(Authentification).filter(
            (Authentification.alias == identifier) |(Authentification.adresse_ip == identifier)).first()
        if user:
            user.is_banned = True
            session.commit()
        else:
            print(f"Aucun utilisateur trouvé avec l'identifiant {identifier}")
        session.close()

    def kick_user(self, identifier, duration):
        session = sessionmaker(bind=engine)()
        user = session.query(Authentification).filter(
            (Authentification.alias == identifier) |(Authentification.adresse_ip == identifier)).first()
        if user:
            kick_expiration = datetime.now() + timedelta(hours=duration)
            user.kick_expiration = kick_expiration
            session.commit()
        else:
            print(f"Aucun utilisateur trouvé avec l'identifiant {identifier}")
        session.close()

    def shutdown_server(self):
        # Envoyer un message à tous les clients pour les informer de l'arrêt
        for alias, client_socket in self.clients.items():
            try:
                client_socket.send("ERROR/SERVER_SHUTDOWN si  nous n'arretez pas le client dans 10 secondes il s'arretera automatiquement pour permettre l'arret du serveur".encode())
            except Exception as e:
                print(f"Erreur lors de l'envoi du message d'arrêt à {alias}: {e}")

        # Fermez les sockets et les ressources ici
        for alias, client_sock in self.clients.items():
            self.update_user_status(alias, "déconnecté")
        self.server_socket.close()
        print("Serveur arrêté.")
    def handle_client(self, client_socket, client_address):
        alias = None
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                    # Le client s'est déconnecté proprement



                self.handle_message(data, client_address, client_socket, self.clients)



                if data.decode().startswith("LOGIN"):
                    _, alias = data.decode().split("/", 2)[:2]
        except Exception as e:
            print(f"Erreur lors de la gestion du client {client_address}: {e}")
            if "Une connexion existante a dû être fermée par l’hôte distant" in str(e) and alias:
                print(f"Le client {alias} s'est déconnecté de manière inattendue.")
                self.update_user_status(alias, "déconnecté")
                self.clients.pop(alias, None)
            for client_alias, client_sock in self.clients.items():
                try:
                    self.send_user_statuses(client_sock)
                except Exception as send_error:
                    print(f"Erreur lors de l'envoi des mises à jour des statuts à {client_alias}: {send_error}")


        finally:
            client_socket.close()


    def update_user_status(self, alias, status):
        session = sessionmaker(bind=engine)()
        user = session.query(Status).filter_by(alias=alias).first()
        if user:
            user.status_connexion = status
            user.timestamp = datetime.now()
            session.commit()
            session.close()

        else:
            print(f"Utilisateur {alias} introuvable pour la mise à jour du statut")




    def handle_message(self, data, client_address, client_socket, clients):
        text = data.decode()

        if text.startswith("CREATE"):
            self.create_new_user(text, client_address, client_socket)
        elif text.startswith("LOGIN"):
            self.login(text,  client_socket)
        elif text.startswith("MP"):
            self.messagePrive(text)
        elif text.startswith("SALON"):
            self.envoi_salon(text, client_socket)
        elif text.startswith("DEMANDE_ACCES_SALON"):
            self.acces_salon(text,client_socket)
        elif text.startswith("ACCEPTER_DEMANDE"):
            self.valid_admin(text, client_socket)

    def send_user_statuses(self, client_socket):
        session = sessionmaker(bind=engine)()
        statuses = session.query(Status).all()
        status_message = "STATUS_UPDATE/" + ",".join([f"{user.alias}:{user.status_connexion}" for user in statuses])
        client_socket.send(status_message.encode())
        session.close()

    def valid_admin(self,texte, client_socket):
        alias=texte.split("/")[1]
        salon=texte.split("/")[2]
        if salon == "Comptabilité":
            salon_i = 2
        elif salon == "Informatique":
            salon_i = 3
        elif salon == "Marketing":
            salon_i = 4
        session = sessionmaker(bind=engine)()
        droits_utilisateur = session.query(Droit_Salon).filter_by(alias=alias).first()
        droits = droits_utilisateur.droits.split(',')
        droits[salon_i] = '1'  # Mettre à jour le droit du salon demandé
        droits_utilisateur.droits = ','.join(droits)

        session.commit()
        client_socket.send("DEMANDE_ACCES_SALON_SUCCESS/Access validé.".encode())

    def acces_salon(self, texte, client_socket):
        salon = texte.split("/")[1]
        alias_source = texte.split("/")[2]

        session = sessionmaker(bind=engine)()
        droits_utilisateur = session.query(Droit_Salon).filter_by(alias=alias_source).first()

        salon_index = 0
        if salon == "Général":
            salon_index = 0
        elif salon == "Blabla":
            salon_index = 1
        elif salon == "Comptabilité":
            salon_index = 2
        elif salon == "Informatique":
            salon_index = 3
        elif salon == "Marketing":
            salon_index = 4

        if droits_utilisateur:
            d = droits_utilisateur.droits.split(",")[salon_index]
            if d=='1':
                client_socket.send("DEMANDE_ACCES_SALON_SUCCESS/vous etes déja dans ce salon.".encode())
            else:
                if salon_index==1:
                    droits = droits_utilisateur.droits.split(',')
                    droits[salon_index] = '1'  # Mettre à jour le droit du salon demandé
                    droits_utilisateur.droits = ','.join(droits)

                    session.commit()
                    client_socket.send("DEMANDE_ACCES_SALON_SUCCESS/Access validé.".encode())
                else:
                    #verification si l'admin est connecter
                    alias= session.query(Authentification).filter_by(droit='1').first()
                    #l'admin est admin si la colonne droit dans la table authentification est egal 1
                    alias=alias.alias

                    if alias in self.clients:
                        socket_admin = self.clients[alias]
                        socket_admin.send(f"DEMANDE_ACCES_SALON_EN_COURS/{alias_source}/{salon}/Access en cours (en attente de l'admin).".encode())
        else:
            client_socket.send("DEMANDE_ACCES_ERROR_SALON/User introuvable.".encode())

        session.close()


    def envoi_salon(self, texte, client_socket):
        # Récupérer les informations du texte
        selected_salon = texte.split("/")[1]
        alias_source = texte.split("/")[2]
        mess = texte.split("/")[3]
        message_salon = mess.split(">>")[1]
        # Vérifier si le salon existe dans la base de données
        session = sessionmaker(bind=engine)()
        salon_existe = session.query(Salon).filter_by(nom=selected_salon).first()
        droits_utilisateur = session.query(Droit_Salon).filter_by(alias=alias_source).first()
        droits = droits_utilisateur.droits.split(',')

        if salon_existe:

            # Vérifier si l'utilisateur a le droit d'envoyer dans ce salon
            droits_utilisateur = session.query(Droit_Salon).filter_by(alias=alias_source).first()

            if droits_utilisateur:
                droits = droits_utilisateur.droits.split(',')

                # Indice du salon dans la liste des droits
                salon_index = 0

                if selected_salon == "Général":
                    salon_index = 0
                elif selected_salon == "Blabla":
                    salon_index = 1
                elif selected_salon == "Comptabilité":
                    salon_index = 2
                elif selected_salon == "Informatique":
                    salon_index = 3
                elif selected_salon == "Marketing":
                    salon_index = 4

                # Vérifier si le salon est autorisé pour l'utilisateur
                if droits[salon_index] == '1':
                    # Envoyer le message à tous les utilisateurs qui ont accès au salon
                    condition=""
                    print("1")
                    for i in range(5):
                        if i != 0 :
                            condition += ","
                        if i != salon_index:
                            condition+="%"
                        else:
                            condition += "1"

                    #ecriture de la condition pour la boucle d'apres
                    print(condition)
                    print("1")
                    for user in session.query(Droit_Salon).filter(Droit_Salon.droits.like(condition)).all():

                        if user.alias in self.clients:
                            user_socket = self.clients[user.alias]

                            user_status = session.query(Status).filter_by(alias=user.alias).first()
                            if user_status and user_status.status_connexion == 'connecté':
                                user_socket.send(
                                    f"messageDuSalon {selected_salon} de la part de {alias_source} >> {message_salon}".encode())
                                print(
                                    f"messageDuSalon {selected_salon} de la part de {alias_source} >> {message_salon}")



                    # Enregistrement du message dans la base de données
                    new_message = Salon(nom=selected_salon, message=message_salon)
                    session.add(new_message)
                    session.commit()
                else:
                    client_socket.send("ERROR_SALON/Droits insuffisants pour envoyer dans ce salon.".encode())
                    print("ERROR_SALON/Droits insuffisants pour envoyer dans ce salon.")
            else:
                client_socket.send("ERROR_SALON/Droits de l'utilisateur non trouvés.".encode())
                print("ERROR_SALON/Droits de l'utilisateur non trouvés.")
        else:
            client_socket.send("ERROR_SALON/Le salon n'existe pas dans la base de données.".encode())
            print("ERROR_SALON/Le salon n'existe pas dans la base de données.")

        session.close()

    def messagePrive(self, text):
        try:
            dest_alias = text.split("/")[1]
            sender_alias = text.split("/")[2]
            message = text.split("/")[3]
            message= message.split(">>")[1]
            # Vérifier si l'alias destinataire existe
            session = sessionmaker(bind=engine)()
            dest_user = session.query(Authentification).filter_by(alias=dest_alias).first()
            src_socket=self.clients[sender_alias]
            if dest_user:
                new_conv = Discussion(alias=sender_alias, destination=dest_alias, conversation=message)
                session.add(new_conv)
                session.commit()
                if dest_alias in self.clients:
                    dest_socket = self.clients[dest_alias]

                    # Envoyer le message privé au destinataire
                    dest_socket.send(f"{sender_alias} >> {message}".encode())
                    # ajouter dans la bas de donneees

                    src_socket.send("MP_SUCCESS".encode())
                    print("MP_SUCCESS")
                else:
                    # Le destinataire n'existe pas
                    src_socket.send(f"ERROR/Le destinataire {dest_alias} n'est pas allume mais rassurez vous tout est enregistrer dans la base de donnee.".encode())
                    print(f"ERROR/Le destinataire {dest_alias} n'est pas allume mais rassurez vous tout est enregistrer dans la base de donnee.")
            else:
                src_socket.send(f"ERROR/Le destinataire {dest_alias} n'existe pas.".encode())
                print(f"ERROR/Le destinataire {dest_alias} n'existe pas.")
        except Exception as e:
            print(f"Erreur lors de la gestion du message privé : {e}")

    def create_new_user(self, text, client_address, client_socket):
        if text.startswith("CREATE"):
            ip_address = str(client_address).split("'")[1]
            alias = text.split("/")[1]
            nom = text.split("/")[2]
            prenom = text.split("/")[3]
            password = text.split("/")[4]
            if len(alias) >= 4 and len(password) >= 4:
                session = sessionmaker(bind=engine)()
                if not session.query(Authentification).filter_by(alias=alias).first():

                    new_user = Authentification(adresse_ip=ip_address, alias=alias, nom=nom, prenom=prenom, password=password)
                    new_droit = Droit_Salon(alias=alias)
                    new_status = Status(alias=alias, status_connexion='déconnecté')

                    session.add(new_user)
                    session.commit()
                    # droit par default
                    session.add(new_droit)
                    session.commit()
                    #status par default
                    session.add(new_status)
                    session.commit()

                    if new_user:
                        # Authentification réussie
                        print(f"Utilisateur {alias} créé avec succès")
                        client_socket.send("CREATE_SUCCESS".encode())
                    else:
                        # Échec de l'authentification
                        print(f"Utilisateur {alias} non créé")
                        client_socket.send("CREATE_FAILURE".encode())
                else:
                    client_socket.send("alias déja existant".encode())
            else:
                print(f"Utilisateur {alias} non créé car il est jugé trop court")
                client_socket.send("CREATE_FAILURE alias ou mot de passe trop court".encode())

    def login(self, text, client_socket):
        if text.startswith("LOGIN"):
            alias = text.split("/")[1]
            password = text.split("/")[2]
            print(alias + " " + password)

            # Vérifier si l'alias et le mot de passe sont corrects dans la table Authentification
            session = sessionmaker(bind=engine)()
            user = session.query(Authentification).filter_by(alias=alias, password=password).first()

            # Vérifier si l'utilisateur est banni ou expulsé
            if user and user.is_banned:
                print(f"Utilisateur {alias} est banni.")
                client_socket.send("ERROR_BAN_FAILURE".encode())
            elif user and user.kick_expiration and user.kick_expiration > datetime.now():
                print(f"Utilisateur {alias} est expulsé jusqu'à {user.kick_expiration}.")
                client_socket.send(f"ERROR_KICK_FAILURE Utilisateur {alias} est expulsé jusqu'à {user.kick_expiration}.".encode())
            elif user:
                # Authentification réussie
                print(f"Utilisateur {alias} authentifié avec succès")
                client_socket.send("AUTH_SUCCESS".encode())
                self.clients[alias] = client_socket
                self.update_user_status(alias, "connecté")
                for client_alias, client_sock in self.clients.items():
                    try:
                        self.send_user_statuses(client_sock)
                    except Exception as e:
                        print(f"Erreur lors de l'envoi des mises à jour des statuts à {client_alias}: {e}")
            else:
                # Échec de l'authentification
                print(f"Échec de l'authentification pour l'utilisateur {alias}")
                client_socket.send("AUTH_FAILURE".encode())

            session.close()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Utilisation: python serveur.py <adresse_ip> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    server = Server(host, port)
    server.start()