from colorama import init, Fore
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
__author__ = "Chauvin Antoine"
__copyright__ = ""
__credits__ = ["Chauvin Antoine"]
__license__ = ""
__version__ = "1.0"
__maintainer__ = "Chauvin Antoine"
__email__ = "antoine.chauvin@live.fr"
__status__ = "Production"


# On démarre l'interpréteur de couleurs
init()

"""

On définis des couleurs afin de faciliter l'affichage (cf. https://pypi.org/project/colorama/)

"""

GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET


class HttpSniffer:
    """
    On définis une classe HttpSniffer qui se chargera
    de filtrer toutes les trames en manipulant le framework scapy
    """

    def __init__(self):
        """
        On définis un sniffer sur le port 80 qui utilisera la carte réseau par défaut (conf.iface)
        On va ensuite traiter nos 'trames' en ajoutant une fonction de callback (prn) qui prendra
        la trame en paramètre
        """

        self.sniffer = sniff(filter="port 80", prn=self.http_filter, store=False)

    def http_filter(self, packet) -> None:
        """
        Méthode de classe qui va filtrer la présence du protocole HTTP (à savoir que le protocole n'est pas sécurisé)
        On va ensuite parser les différents arguments du paquet
        """

        # Explicite
        if packet.haslayer(HTTPRequest):

            # On se charge de récupérer l'hôte du packet et la destination qui constitueront l'url en bytes!
            url = packet[HTTPRequest].Host + packet[HTTPRequest].Path

            # On récupère l'adresse ip source
            ip = packet[IP].src

            # On récupère la méthode
            method = packet[HTTPRequest].Method

            # on formatte les variables et les affiches en couleur avec colorama
            print(f"\n{GREEN}[+] {ip} Requested {url} with {method.decode()}{RESET}")

            """
            On ajoute une condition pour savoir si des informations ont été transmises durant la requête
            Si oui on charge les données et on les affiches
            """
            
            if packet.haslayer(Raw) and method.decode() == "POST":
                print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")


if __name__ == "__main__":
    my_sniffer = HttpSniffer()
