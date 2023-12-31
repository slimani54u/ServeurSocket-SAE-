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
db_connection_string = 'mysql+mysqlconnector://toto:toto@localhost:3306/serveur_discussion'
engine = create_engine(db_connection_string)
metadata.create_all(engine)

class Authentification(Base):
    """
        Représente la table 'Authentification' dans la base de données. Cette classe sert à stocker les informations d'authentification des utilisateurs, y compris leurs alias, mots de passe et autres informations personnelles.
        """
    __table__ = Table('Authentification', metadata, autoload_with=engine)

class Status(Base):
    """
        Modélise la table 'Status' dans la base de données. Cette classe est utilisée pour suivre le statut de connexion des utilisateurs (par exemple, connecté ou déconnecté) et enregistrer la dernière fois qu'ils ont modifié leur statut.
        """
    __table__ = Table('Status', metadata, autoload_with=engine)

class Salon(Base):
    """
        Correspond à la table 'Salon' dans la base de données. Utilisée pour gérer les différents salons de discussion, cette classe stocke les informations liées aux différents salons, comme leur nom et les messages échangés.
        """
    __table__ = Table('Salon', metadata, autoload_with=engine)

class Discussion(Base):
    """
        Représente la table 'Discussion' dans la base de données. Elle est utilisée pour stocker l'historique des conversations privées entre les utilisateurs, y compris l'expéditeur, le destinataire et le contenu des messages.
        """
    __table__ = Table('Discussion', metadata, autoload_with=engine)

class Droit_Salon(Base):
    """
       Modèle la table 'Droit_Salon' dans la base de données. Cette classe gère les droits d'accès des utilisateurs aux différents salons de discussion, déterminant quels salons ils peuvent voir ou dans lesquels ils peuvent poster.
       """
    __table__ = Table('Droit_Salon', metadata, autoload_with=engine)

class Server:
    """
        Classe principale pour la gestion du serveur de discussion. Elle initialise le serveur, gère les connexions et déconnexions des clients, traite les messages reçus et maintient l'état global du serveur.
        """
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
        """
            Lance le serveur et attend les connexions entrantes des clients. Cette méthode initialise également un thread séparé pour écouter les commandes d'arrêt du serveur.

            Le serveur est configuré pour accepter les connexions entrantes jusqu'à ce qu'une commande d'arrêt soit reçue. Chaque client connecté est géré par un thread séparé. En cas de timeout ou d'autres exceptions, le serveur continue son fonctionnement normal, à l'exception des erreurs inattendues qui sont imprimées sur la console.
            """
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
        """
           Écoute en continu pour des commandes administratives via l'entrée standard.

           Cette méthode gère les commandes suivantes :
           - "kill" : Arrête le serveur.
           - "ban <identifiant>" : Bannit l'utilisateur spécifié.
           - "kick <identifiant> <durée>" : Expulse l'utilisateur spécifié pour une durée donnée (en heures).
           - "unban <identifiant>" : Débannit l'utilisateur spécifié.
           - "unkick <identifiant>" : Annule l'expulsion de l'utilisateur spécifié.

           Les commandes sont lues à partir de l'entrée standard et traitées en fonction de leur type.
           Les actions de ban, kick, unban et unkick sont déléguées aux méthodes correspondantes de la classe.
           """
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
        """
           Annule l'expulsion d'un utilisateur du serveur.

           Cette méthode recherche un utilisateur dans la base de données, soit par son alias, soit par son adresse IP.
           Si l'utilisateur est trouvé, la date d'expiration de son expulsion est réinitialisée à None,
           permettant ainsi à l'utilisateur de se reconnecter au serveur.

           :param identifier: L'alias ou l'adresse IP de l'utilisateur à réintégrer.
           :type identifier: str
           """
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
        """
            Annule le bannissement d'un utilisateur du serveur.

            Cette méthode recherche un utilisateur dans la base de données, soit par son alias, soit par son adresse IP.
            Si l'utilisateur est trouvé, son état de bannissement est réinitialisé à False, permettant ainsi à l'utilisateur
            de se reconnecter au serveur.

            :param identifier: L'alias ou l'adresse IP de l'utilisateur à débannir.
            :type identifier: str
            """
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
        """
            Bannit un utilisateur du serveur.

            Cette méthode permet de rechercher un utilisateur dans la base de données, soit par son alias, soit par son adresse IP.
            Si l'utilisateur est trouvé, son état de bannissement est modifié à True, empêchant ainsi l'utilisateur
            de se reconnecter au serveur.

            :param identifier: L'alias ou l'adresse IP de l'utilisateur à bannir.
            :type identifier: str
            """
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
        """
            Expulse temporairement un utilisateur du serveur.

            Cette méthode recherche un utilisateur dans la base de données par son alias ou son adresse IP. Si l'utilisateur est trouvé,
            son temps d'expulsion est défini pour une durée spécifique. L'utilisateur ne pourra pas se reconnecter au serveur
            jusqu'à ce que cette période expire.

            :param identifier: L'alias ou l'adresse IP de l'utilisateur à expulser.
            :type identifier: str
            :param duration: La durée de l'expulsion en heures.
            :type duration: int
            """
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
        """
            Arrête le serveur en envoyant un message de fermeture à tous les clients connectés.

            Cette méthode parcourt tous les clients connectés, envoie un message pour les informer de l'arrêt imminent du serveur,
            et ferme les sockets client. Elle met à jour le statut des utilisateurs comme 'déconnecté' dans la base de données
            avant de fermer le socket du serveur.
            """
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
        """
            Gère la communication avec un client connecté.

            Cette méthode est appelée dans un thread séparé pour chaque client qui se connecte au serveur.
            Elle écoute les messages entrants du client, les traite et répond en conséquence.
            En cas de déconnexion inattendue du client, la méthode met à jour son statut et libère les ressources.

            :param client_socket: Le socket du client connecté.
            :type client_socket: socket.socket
            :param client_address: L'adresse du client connecté.
            :type client_address: tuple
            """
        alias = None
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                    



                self.handle_message(data, client_address, client_socket)



                if data.decode().startswith("LOGIN"):
                    _, alias = data.decode().split("/", 2)[:2]
        except Exception as e:
            print(f"Erreur lors de la gestion du client {client_address}: {e}")
            if alias:
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
        """
            Met à jour le statut de connexion d'un utilisateur dans la base de données.

            Cette méthode trouve l'utilisateur dans la base de données par son alias et met à jour son statut
            de connexion ainsi que le timestamp de la dernière modification.

            :param alias: L'alias de l'utilisateur.
            :type alias: str
            :param status: Le nouveau statut de connexion.
            :type status: str
            """
        session = sessionmaker(bind=engine)()
        user = session.query(Status).filter_by(alias=alias).first()
        if user:
            user.status_connexion = status
            user.timestamp = datetime.now()
            session.commit()
            session.close()

        else:
            print(f"Utilisateur {alias} introuvable pour la mise à jour du statut")




    def handle_message(self, data, client_address, client_socket):
        """
            Traite un message reçu d'un client.

            Cette méthode détermine le type de message reçu (création d'un utilisateur, login, message privé, etc.)
            et appelle la fonction appropriée pour gérer la demande.

            :param data: Les données reçues du client.
            :type data: bytes
            :param client_address: L'adresse du client.
            :type client_address: tuple
            :param client_socket: Le socket du client.
            :type client_socket: socket.socket
            """
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
        """
            Envoie les statuts de connexion de tous les utilisateurs au client spécifié.

            Cette méthode récupère les statuts de connexion de tous les utilisateurs dans la base de données,
            les formate en un message unique, et les envoie au client spécifié.

            :param client_socket: Le socket du client auquel envoyer les statuts.
            :type client_socket: socket.socket
            """
        session = sessionmaker(bind=engine)()
        statuses = session.query(Status).all()
        status_message = "STATUS_UPDATE/" + ",".join([f"{user.alias}:{user.status_connexion}" for user in statuses])
        client_socket.send(status_message.encode())
        session.close()

    def valid_admin(self,texte, client_socket):
        """
            Traite la demande d'administration d'un salon.

            Cette méthode est appelée lorsqu'un utilisateur demande des droits d'administration sur un salon spécifique.
            Elle vérifie les droits de l'utilisateur et met à jour ses droits si nécessaire.

            :param texte: Le texte contenant l'alias de l'utilisateur et le nom du salon.
            :type texte: str
            :param client_socket: Le socket du client demandeur.
            :type client_socket: socket.socket
            """
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
        """
            Gère la demande d'accès à un salon.

            Cette méthode vérifie si l'utilisateur demandeur a les droits pour accéder au salon spécifié.
            Elle envoie une réponse appropriée au client, soit confirmant l'accès, soit informant de l'attente de validation par un administrateur.

            :param texte: Le texte contenant le nom du salon et l'alias de l'utilisateur demandeur.
            :type texte: str
            :param client_socket: Le socket du client demandeur.
            :type client_socket: socket.socket
            """
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
        """
            Gère l'envoi de messages dans un salon spécifique.

            Cette méthode vérifie si l'utilisateur a le droit d'envoyer des messages dans le salon demandé.
            Si autorisé, elle envoie le message à tous les utilisateurs ayant accès à ce salon et enregistre le message dans la base de données.

            :param texte: Le texte contenant le nom du salon, l'alias de l'expéditeur et le message.
            :type texte: str
            :param client_socket: Le socket du client envoyant le message.
            :type client_socket: socket.socket
            """
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
        """
    Gère l'envoi de messages privés entre utilisateurs.

    Cette méthode envoie un message privé d'un utilisateur à un autre et enregistre la conversation dans la base de données.
    Elle gère également le cas où le destinataire n'est pas connecté ou n'existe pas.

    :param text: Le texte contenant les alias de l'expéditeur et du destinataire, ainsi que le message.
    :type text: str
    """
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
        """
            Crée un nouvel utilisateur dans la base de données.

            Cette méthode crée un nouvel utilisateur avec les informations fournies et définit ses droits et son statut par défaut.
            Elle gère également les cas où l'alias est déjà pris ou si les informations sont insuffisantes.

            :param text: Le texte contenant les informations de l'utilisateur (adresse IP, alias, nom, prénom, mot de passe).
            :type text: str
            :param client_address: L'adresse du client effectuant la requête.
            :type client_address: str
            :param client_socket: Le socket du client effectuant la requête.
            :type client_socket: socket.socket
            """
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
        """
            Gère le processus de connexion d'un utilisateur.

            Cette méthode vérifie les informations de connexion (alias et mot de passe) et le statut de l'utilisateur (banni ou expulsé).
            En cas de succès, elle envoie une confirmation au client et met à jour le statut de l'utilisateur dans la base de données.

            :param text: Le texte contenant l'alias et le mot de passe de l'utilisateur.
            :type text: str
            :param client_socket: Le socket du client essayant de se connecter.
            :type client_socket: socket.socket
            """
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
    """
        Point d'entrée principal du script serveur.py.

        Ce script initialise et démarre le serveur de discussion. Il prend deux arguments en ligne de commande : 
        l'adresse IP sur laquelle le serveur doit écouter et le port sur lequel le serveur doit accepter les connexions.

        Exemple d'utilisation : 
        python serveur.py 127.0.0.1 5555

        Si les arguments ne sont pas fournis correctement, le script affiche un message d'usage et se termine.
        """
    if len(sys.argv) != 3:
        print("Utilisation: python serveur.py <adresse_ip> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    server = Server(host, port)
    server.start()