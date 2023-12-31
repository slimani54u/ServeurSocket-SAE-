import sys
import socket
import threading
from time import sleep

from PyQt6.QtWidgets import QApplication, QStackedWidget, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, \
    QTextEdit, QTabWidget, QListWidget, QListWidgetItem, QComboBox, QMessageBox
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import Qt, QMetaObject, pyqtSignal

# Définition des styles généraux
general_font = QFont("Arial", 12)
button_style = "background-color: #007bff; color: white; padding: 5px;"
input_style = "border: 1px solid #ced4da; padding: 5px; border-radius: 3px;"
label_style = "color: #212529;"
class LoginPage(QWidget):
    """
        La page de connexion de l'application client. Permet aux utilisateurs de se connecter ou de créer un nouveau compte.

        :param stacked_widget: Le widget empilé pour la navigation entre les pages.
        :param client_socket: Le socket client pour communiquer avec le serveur.
        """
    def __init__(self, stacked_widget, client_socket):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.client_socket = client_socket
        self.init_ui()

    def init_ui(self):
        """
            Initialise l'interface utilisateur de la page de connexion. Définit les champs, boutons et mise en page.
                """
        # Définir une police générale pour la page
        font = QFont("Arial", 12)

        # Champs de saisie Alias
        self.alias = QLineEdit(self)
        self.alias.setFont(font)
        self.alias.setPlaceholderText("Utilisateur")
        self.alias.setStyleSheet("border: 1px solid #ced4da; padding: 5px; border-radius: 3px;")

        # Champs de saisie Mot de passe
        self.password = QLineEdit(self)
        self.password.setFont(font)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Mot de passe")
        self.password.setStyleSheet("border: 1px solid #ced4da; padding: 5px; border-radius: 3px;")

        # Bouton de connexion
        self.login_button = QPushButton('Se connecter', self)
        self.login_button.setFont(font)
        self.login_button.setStyleSheet("background-color: #007bff; color: white; padding: 5px;")

        # Bouton de création de compte
        self.create_account_button = QPushButton('Créer un compte', self)
        self.create_account_button.setFont(font)
        self.create_account_button.setStyleSheet("background-color: #6c757d; color: white; padding: 5px;")

        # Mise en page
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel('Utilisateur:'))
        layout.addWidget(self.alias)
        layout.addWidget(QLabel('Mot de passe:'))
        layout.addWidget(self.password)
        layout.addWidget(self.login_button)
        layout.addWidget(self.create_account_button)

        self.setLayout(layout)

        # Connexions des boutons
        self.login_button.clicked.connect(self.login)
        self.create_account_button.clicked.connect(self.show_create_account)

    def show_error_message(self, message):
        """
                Affiche un message d'erreur dans une boîte de dialogue.

                :param message: Le message d'erreur à afficher.
                """
        error_dialog = QMessageBox()

        error_dialog.setText(message)
        error_dialog.setWindowTitle("Erreur de Connexion")
        error_dialog.exec()

    def login(self):
        """
                Tente de se connecter au serveur avec les informations d'identification fournies. Change la page en cas de succès.
                """
        alias = self.alias.text()
        password = self.password.text()

        try:
            # Envoi de la demande de connexion au serveur
            self.client_socket.send(f"LOGIN/{alias}/{password}".encode())

            # Réception de la réponse du serveur
            response = self.client_socket.recv(1024).decode()

            if response == "AUTH_SUCCESS":
                print("Connexion établie avec le serveur")
                messaging_page = MessagingPage(self.client_socket, alias)
                self.stacked_widget.addWidget(messaging_page)
                self.stacked_widget.setCurrentWidget(messaging_page)
            else:
                # Afficher le message d'erreur en cas d'échec de connexion
                self.show_error_message(response)

        except Exception as e:
            print(f"Erreur lors de la connexion au serveur : {e}")
            self.show_error_message("Erreur lors de la connexion au serveur.")

    def show_create_account(self):
        """
            Change vers la page de création de compte.
                """
        self.stacked_widget.setCurrentIndex(1)  # Passer à la page de création de compte

class CreateAccountPage(QWidget):
    """
        La page de création de compte de l'application client. Permet aux utilisateurs de créer un nouveau compte.

        :param stacked_widget: Le widget empilé pour la navigation entre les pages.
        :param client_socket: Le socket client pour communiquer avec le serveur.
        """
    def __init__(self, stacked_widget, client_socket):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.client_socket = client_socket
        self.init_ui()

    def init_ui(self):
        """
            Initialise l'interface utilisateur pour la création de compte.
                """
        self.alias_input = QLineEdit(self)
        self.nom_input = QLineEdit(self)
        self.prenom_input = QLineEdit(self)
        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        self.create_account_button = QPushButton('Créer un compte', self)
        self.create_account_button.clicked.connect(self.create_account)

        self.return_to_login_button = QPushButton('Retour à la connexion', self)
        self.return_to_login_button.clicked.connect(self.return_to_login)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel('Prénom:'))
        layout.addWidget(self.prenom_input)
        layout.addWidget(QLabel('Nom:'))
        layout.addWidget(self.nom_input)
        layout.addWidget(QLabel('Alias:'))
        layout.addWidget(self.alias_input)
        layout.addWidget(QLabel('Mot de passe:'))
        layout.addWidget(self.password)
        layout.addWidget(self.create_account_button)
        layout.addWidget(self.return_to_login_button)

        self.setLayout(layout)

    def show_error_message(self, message):
        """
                Affiche un message d'erreur dans une boîte de dialogue.

                :param message: Le message d'erreur à afficher.
                """
        error_dialog = QMessageBox()

        error_dialog.setText(message)
        error_dialog.setWindowTitle("Erreur de Création")
        error_dialog.exec()
    def create_account(self):
        """
            Envoie une demande de création de compte au serveur et gère la réponse.
                """
        prenom = self.prenom_input.text()
        nom = self.nom_input.text()
        alias = self.alias_input.text()
        password = self.password.text()
        # Ajouter la logique pour créer un compte avec le serveur
        if self.client_socket is not None:
            self.client_socket.send(f"CREATE/{alias}/{nom}/{prenom}/{password}".encode())

            response = self.client_socket.recv(1024).decode()

            # Après la création du compte, revenir à la page de connexion
            self.stacked_widget.setCurrentIndex(0)
            if response == "CREATE_SUCCESS":
                print("utilisateur créé")
                # Ramène dans une page de messagerie où à gauche je peux choisir le destinataire par alias
                # et à droite je peux choisir le salon
            else:
                # Te remet dans la page de la messagerie
                print("échec de la création")
                print(f"{response}")
                self.show_error_message(response)

    def return_to_login(self):
        """
            Retourne à la page de connexion.
                """
        self.stacked_widget.setCurrentIndex(0)  # Revenir à la page de connexion

class MessagingPage(QWidget):
    """
        La page de messagerie de l'application client. Permet aux utilisateurs d'envoyer des messages privés ou dans des salons.

        :param client_socket: Le socket client pour communiquer avec le serveur.
        :param alias_source: L'alias de l'utilisateur actuellement connecté.
        """
    # signal pour erreur
    error_signal = pyqtSignal(str)
    shutdown_signal = pyqtSignal()

    def __init__(self, client_socket, alias_source):
        super().__init__()
        self.client_socket = client_socket
        self.alias_source = alias_source
        self.init_ui()

        # Connecter le signal au slot
        self.error_signal.connect(self.show_error)
        self.shutdown_signal.connect(self.handle_shutdown)

    def init_ui(self):
        """
            Initialise l'interface utilisateur de la page de messagerie.
                """
        # Widgets pour envoyer des messages privés
        self.alias_destinataire_input = QLineEdit(self)
        self.message_prive_input = QLineEdit(self)
        self.select_destinataire_button = QPushButton('Envoyer Message Privé', self)
        self.select_destinataire_button.clicked.connect(self.select_destinataire)

        # Widgets pour envoyer des messages dans le salon
        self.salon_box = QComboBox(self)
        self.salon_box.addItems(['Général', 'Blabla', 'Comptabilité', 'Informatique', 'Marketing'])
        self.message_salon_input = QLineEdit(self)  # Champ de texte pour écrire le message du salon
        self.select_salon_button = QPushButton('Envoyer dans le Salon', self)
        self.select_salon_button.clicked.connect(self.select_salon)

        # Zone de texte pour afficher les messages
        self.message_display = QTextEdit(self)
        self.message_display.setReadOnly(True)

        # Onglets pour choisir entre Message Privé et Salon
        self.tabs = QTabWidget(self)
        self.tab_message_prive = QWidget()
        self.tab_salon = QWidget()

        # Layouts pour chaque onglet
        layout_message_prive = QVBoxLayout(self.tab_message_prive)
        layout_message_prive.addWidget(QLabel('Alias Destinataire:'))
        layout_message_prive.addWidget(self.alias_destinataire_input)
        layout_message_prive.addWidget(QLabel('Message Privé:'))
        layout_message_prive.addWidget(self.message_prive_input)
        layout_message_prive.addWidget(self.select_destinataire_button)

        layout_salon = QVBoxLayout(self.tab_salon)
        layout_salon.addWidget(QLabel('Choisir Salon:'))
        layout_salon.addWidget(self.salon_box)
        layout_salon.addWidget(QLabel('Message dans le Salon:'))
        layout_salon.addWidget(self.message_salon_input)
        layout_salon.addWidget(self.select_salon_button)

        # Ajouter les onglets à l'interface principale
        self.tabs.addTab(self.tab_message_prive, 'Message Privé')
        self.tabs.addTab(self.tab_salon, 'Salon')

        # Layout principal
        main_layout = QVBoxLayout(self)
        main_layout.addWidget(QLabel('Messagerie'))
        main_layout.addWidget(self.tabs)
        main_layout.addWidget(self.message_display)  # Ajout du widget d'affichage des messages

        self.setLayout(main_layout)
        self.demande_acces_button = QPushButton("Demander l'accès au Salon", self)
        self.demande_acces_button.clicked.connect(self.demande_acces_salon)
        layout_salon.addWidget(self.demande_acces_button)

        self.tab_demandes_acces = DemandesAccesTab(self.client_socket)
        self.tabs.addTab(self.tab_demandes_acces, 'Demandes Accès')

        # Démarrer le thread pour recevoir les messages
        self.receive_thread = threading.Thread(target=self.receive_message, daemon=True)
        self.receive_thread.start()

        #status
        self.tab_status = StatusPage(self.client_socket, self.alias_source)
        self.tabs.addTab(self.tab_status, 'Status')




    def show_error(self, message):
        """
                Affiche un message d'erreur dans une boîte de dialogue.

                :param message: Le message d'erreur à afficher.
                """
        QMessageBox.critical(self, "Erreur", message)
    def select_destinataire(self):
        """
                Envoie un message privé à l'utilisateur sélectionné.
                """
        alias_destinataire = self.alias_destinataire_input.text()
        message_priv = self.message_prive_input.text()
        self.client_socket.send(f"MP/{alias_destinataire}/{self.alias_source}/>>{message_priv}".encode())

    def handle_shutdown(self):
        """
            Gère la fermeture de l'application lors de la réception d'un signal d'arrêt du serveur.
                """
        # Logique pour gérer la fermeture de l'interface utilisateur
        self.client_socket.close()
        QApplication.quit()
    def receive_message(self):
        """
                Thread pour recevoir les messages du serveur et les afficher dans l'interface utilisateur.
                """
        while True:
            data = self.client_socket.recv(1024)
            if data:
                decoded_data = data.decode()
                print(decoded_data)
                if len(decoded_data.split(">>")) > 1:
                    alias = decoded_data.split(">>")[0]
                    mess = decoded_data.split(">>")[1]
                    received_message = f"Message reçu de {alias}: {mess}\n"
                    # Utilisation de append pour ajouter le message sans effacer les précédents
                    self.message_display.append(received_message)
                if decoded_data.startswith("STATUS_UPDATE"):
                    self.tab_status.update_status(decoded_data[13:])
                if decoded_data.startswith("ERROR"):
                    self.error_signal.emit(decoded_data)
                    if decoded_data.startswith("ERROR/SERVER_SHUTDOWN"):
                        sleep(10)
                        self.shutdown_signal.emit()
                        break
                if decoded_data.startswith(f"DEMANDE_ACCES_SALON_EN_COURS"):
                    # Extraire l'alias du demandeur et le nom du salon de la demande
                    _, alias_demandeur, salon_demande, _ = decoded_data.split('/')
                    # Appeler la méthode update_demandes_list de la classe DemandesAccesTab
                    self.tab_demandes_acces.update_demandes_list(
                        f"DEMANDE_ACCES_SALON_EN_COURS/{alias_demandeur}/{salon_demande}")

                if decoded_data.startswith(f"Status"):
                    _, alias, status =decoded_data.split('/')


            else:
                break

    def select_salon(self):
        """
            Envoie un message dans le salon sélectionné.
                """
        selected_salon = self.salon_box.currentText()
        message_salon = self.message_salon_input.text()  # Récupérer le message du salon depuis le champ de texte
        self.client_socket.send(f"SALON/{selected_salon}/{self.alias_source}/>>{message_salon}".encode())
        print(f"SALON/{selected_salon}/{self.alias_source}/>>{message_salon}")

    def demande_acces_salon(self):
        """
                Envoie une demande d'accès à un salon au serveur.
                """
        selected_salon = self.salon_box.currentText()
        self.client_socket.send(f"DEMANDE_ACCES_SALON/{selected_salon}/{self.alias_source}".encode())

class DemandesAccesTab(QWidget):
    """
       Un onglet dans l'interface utilisateur du client pour gérer les demandes d'accès aux salons.

       :param client_socket: Le socket client pour communiquer avec le serveur.
       """
    def __init__(self, client_socket):
        super().__init__()
        self.client_socket = client_socket
        self.init_ui()

    def init_ui(self):
        """
            Initialise l'interface utilisateur pour l'onglet des demandes d'accès.
                """
        # Widget de liste pour afficher les demandes
        self.demandes_list_widget = QListWidget(self)

        # Boutons pour accepter ou refuser les demandes
        self.accepter_button = QPushButton('Accepter', self)
        self.refuser_button = QPushButton('Refuser', self)
        self.accepter_button.clicked.connect(self.accepter_demande)
        self.refuser_button.clicked.connect(self.refuser_demande)

        # Layout
        layout = QVBoxLayout(self)
        layout.addWidget(self.demandes_list_widget)
        layout.addWidget(self.accepter_button)
        layout.addWidget(self.refuser_button)
        self.setLayout(layout)

    def update_demandes_list(self, demande_text):
        """
                Met à jour la liste des demandes d'accès avec une nouvelle demande.

                :param demande_text: Le texte de la demande à ajouter à la liste.
                """
        # Ajouter la nouvelle demande à la liste
        item = QListWidgetItem(demande_text)
        self.demandes_list_widget.addItem(item)

    def accepter_demande(self):
        """
            Accepte la demande d'accès sélectionnée et envoie une confirmation au serveur.
                """
        # Récupérer la demande sélectionnée dans la liste
        demande_item = self.demandes_list_widget.currentItem()
        if demande_item:
            demande_text = demande_item.text()
            print("1")
            # Vérifier si la demande commence par "DEMANDE_ACCES_SALON_EN_COURS"
            if demande_text.startswith("DEMANDE_ACCES_SALON_EN_COURS"):
                print(demande_text.split('/'))
                # Extraire l'alias et le salon de la demande
                try:
                    alias_demandeur=demande_text.split('/')[1]
                    salon_demande=demande_text.split('/')[2]
                except Exception as e:
                    print(f"Erreur lors de la division de la demande : {e}")

                print("2")
                # Envoyer un message au serveur pour accepter la demande
                self.client_socket.send(f"ACCEPTER_DEMANDE_ACCES/{alias_demandeur}/{salon_demande}".encode())

            # Supprimer la demande de la liste
            row = self.demandes_list_widget.row(demande_item)
            self.demandes_list_widget.takeItem(row)

    def refuser_demande(self):
        """
                Refuse la demande d'accès sélectionnée et envoie une notification de refus au serveur.
                """
        # Récupérer la demande sélectionnée dans la liste
        demande_item = self.demandes_list_widget.currentItem()
        if demande_item:
            demande_text = demande_item.text()
            alias_demandeur = demande_text.split('/')[1]
            salon_demande = demande_text.split('/')[2]

            # Envoyer un message au serveur pour refuser la demande
            self.client_socket.send(f"REFUSER_DEMANDE_ACCES/{alias_demandeur}/{salon_demande}".encode())

            # Supprimer la demande de la liste
            row = self.demandes_list_widget.row(demande_item)
            self.demandes_list_widget.takeItem(row)

class StatusPage(QWidget):
    """
        Un onglet dans l'interface utilisateur du client pour afficher les statuts des utilisateurs.

        :param client_socket: Le socket client pour communiquer avec le serveur.
        :param alias_source: L'alias de l'utilisateur actuellement connecté.
        """
    def __init__(self, client_socket, alias_source):
        super().__init__()
        self.client_socket = client_socket
        self.alias_source = alias_source
        self.user_status_list = QListWidget(self)  # Liste pour afficher les statuts
        self.init_ui()

    def init_ui(self):
        """
            Initialise l'interface utilisateur pour l'onglet des statuts des utilisateurs.
                """
        layout = QVBoxLayout(self)
        layout.addWidget(self.user_status_list)
        self.setLayout(layout)

    def update_status(self, status_data):
        """
                Met à jour la liste des statuts des utilisateurs.

                :param status_data: Les données des statuts des utilisateurs à afficher.
                """
        self.user_status_list.clear()  # Effacer les entrées existantes
        for status in status_data.split(','):
            alias, user_status = status.split(':')
            self.user_status_list.addItem(f"{alias} - {user_status}")



if __name__ == '__main__':
    # Initialisation et exécution de l'application
    """
        Point d'entrée principal pour l'application cliente.

        L'application cliente démarre en se connectant au serveur spécifié et en affichant l'interface de connexion.
        Les arguments nécessaires sont l'adresse IP et le port du serveur.
        """
    if len(sys.argv) != 3:
        print("Utilisation: python client.py <adresse_ip> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    app = QApplication(sys.argv)
    app.setStyleSheet("QWidget { font-size: 12pt; font-family: Arial; }")  # Style par défaut pour les widgets

    stacked_widget = QStackedWidget()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
    except Exception as e:
        print(f"Erreur de connexion : {e}")
        sys.exit(1)

    login_page = LoginPage(stacked_widget, client_socket)
    create_account_page = CreateAccountPage(stacked_widget, client_socket)

    stacked_widget.addWidget(login_page)
    stacked_widget.addWidget(create_account_page)
    stacked_widget.resize(500, 500)  # Ajustement de la taille par défaut de la fenêtre
    stacked_widget.setStyleSheet("background-color: #f5f5f5;")  # Couleur de fond de la fenêtre

    stacked_widget.show()
    sys.exit(app.exec())