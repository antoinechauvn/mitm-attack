# Exploitation du protocole ARP afin d'obtenir des informations confidentielles en utilisant l'attaque MITM (Man-in-the-middle)
![image](https://user-images.githubusercontent.com/83721477/137015747-f61c8726-15ed-468e-9c48-3bd91eafc6b7.png)

>Un système « A » tente d’établir une connexion cryptée avec un système « B ». Au lieu de cela, le flux de données est dévié par un hacker de sorte que la connexion cryptée entre le système « A » et le système « C » fonctionne en premier, le hacker substitue le cryptage, puis les données sont à nouveau transmises à partir de ce dernier au système « B » : ainsi celui qui a le contrôle du système C (le plus souvent un agresseur), peut lire, enregistrer ou manipuler tout trafic et communication sans que les autres partenaires prennent conscience de l’existence d’un tiers. Dans le contexte du World Wide Web, le système « C » se présente au système « A » comme un serveur Web et au système « B » comme un navigateur Internet.

>Attaque de l’homme du milieu : schéma de l’intrusion
Pour infiltrer ainsi le trafic de données entre deux ou plusieurs systèmes, les hackers utilisent diverses techniques sont basées sur les vulnérabilités connues de la communication Internet. Une cible vulnérable pour les attaques de l’homme du milieu en réseau local interne est par exemple le service DHCP (Dynamic Host Configuration Protocol), qui est responsable de l’attribution des adresses IP locales, et le système ARP (Address Resolution Protocol) qui détermine l’adresse matérielle (Media-Access-Control, MAC). De manière générale, les attaques HDM peuvent s’effectuer par le biais de la manipulation des serveurs DNS (système de noms de domaine), ces derniers sont responsables de la résolution des adresses Internet en adresses IP publiques. Par ailleurs, les hackers exploitent les vulnérabilités d’un logiciel de navigation obsolète ou fournissent un accès WIFI corrompu à des utilisateurs peu méfiants.

>En règle générale, ces schémas d’attaques sont automatisés par un logiciel. Quand les attaques sont prises en charge par une interaction humaine en temps réel, on parle alors d’attaque « Human-Assisted ».

## Attaque basée sur DHCP
>Dans le cas d’une attaque basée sur DHCP, l’ordinateur propre du hacker (ou celui qui est sous son contrôle) au sein d’un réseau local (LAN) est présenté en tant que serveur DHCP. Un serveur DHCP est un élément important dans le réseau local, il est en effet responsable de l’attribution de la configuration réseau à d’autres ordinateurs du LAN. Ceci est normalement réalisé automatiquement : dès qu’un ordinateur se connecte au LAN, le client DHCP du système d’exploitation réclame des informations comme l’adresse IP locale, le masque de réseau, l’adresse passerelle par défaut ainsi que l’adresse de serveur DNS approprié. Pour ce faire, il envoie un message de diffusion générale à tous les appareils dans le LAN et attend la confirmation d’un serveur DHCP. La première réponse détaillée est alors acceptée. 

>Ceci permet aux hackers par l’intermédiaire d’un serveur DHCP factice de contrôler l’allocation des adresses IP locales, d’entrer n’importe quelle passerelle par défaut et serveur DNS sur les ordinateurs trompés et ainsi de détourner le trafic sortant vers n’importe quel autre ordinateur pour intercepter ou manipuler le contenu.

>Comme ce modèle d’attaque est basé sur la manipulation du système DHCP, il est nommé DHCP Spoofing (pour « usurpation » en français). Dans ce cas de figure, la condition préalable pour une attaque de l’homme du milieu est que l’attaquant doit être sur le même réseau local (LAN) que la victime. Par conséquent le risque de subir une attaque basée sur DHCP est renforcé lors de l’utilisation d’un réseau public sans fil ou d’un réseau LAN d’un hôtel par exemple.

>Les mesures préventives pour empêcher un DHCP Spoofing se limitent en général à avoir une approche vigilante et réfléchie concernant l’utilisation de réseaux inconnus. Il est aussi conseillé de ne pas utiliser les applications avec des données sensibles comme la banque en ligne par exemple ou d’effectuer un achat sur une boutique ou un portail Web en dehors de son réseau privé chez soi ou du réseau d’entreprise au bureau.

## ARP-Cache-Poisoning : empoisonnement du cache ARP
>L’ARP (Address Resolution Protocol) est un protocole réseau qui effectue la traduction d’une adresse de protocole de couche réseau (l’adresse IP interne du LAN) en une adresse matérielle ou physique (adresse MAC, souvent une adresse Ethernet). Pour qu’un ordinateur puisse envoyer des paquets de données au sein d’un réseau, il doit d’abord connaître l’adresse matérielle du système récepteur. À cette fin, une requête ARP est envoyée comme adresse MAC diffusée à tous les systèmes sur le LAN. Ceci comprend à la fois l’adresse MAC et l’adresse IP de l’ordinateur demandeur et l’adresse IP du système ciblé. Si un ordinateur sur le réseau reçoit une telle demande ARP, elle vérifie si le paquet contient sa propre adresse IP en tant que destinataire IP. Si tel est le cas, une réponse ARP est alors envoyée avec l’adresse MAC recherchée au système demandeur.

>Cette attribution de l’adresse MAC à l’adresse IP locale est stockée sous forme de tableau dans le cache ARP de l’ordinateur demandeur. C’est ici que l’empoisonnement du cache ARP est effectué. Le but de ce modèle d’attaque est de pouvoir manipuler les tableaux ARP de différents ordinateurs du réseau par le biais de fausses réponses ARP, par exemple un ordinateur sous le contrôle de l’attaquant est déterminé comme un point d’accès WIFI ou comme une passerelle à Internet.

>Si une telle usurpation d’ARP est réussie, les hackers ont alors la capacité de lire, d’enregistrer ou encore de manipuler tout le trafic sortant d’un ordinateur infecté, avant qu’il ne soit envoyé vers la passerelle réelle. Comme pour le DHCP Spoofing, un empoisonnement de cache ARP est seulement possible si l’attaquant se trouve sur le même réseau local (LAN) que le système de la victime. Une attaque de l’« homme du milieu » peut être facilement mise en œuvre avec des programmes simples comme l’outil gratuit Cain & Abel, qui a initialement été développé pour l’identification des mots de passe perdus, ou encore avec le logiciel Ettercap.

>Comme pour les attaques basées sur DHCP, les utilisateurs qui utilisent un réseau local corrompu ont peu de moyens pour se défendre contre l’ARP Spoofing. La prévention est la meilleure solution, il est donc nécessaire d’éviter l’utilisation de réseaux inconnus, ou alors de les utiliser judicieusement et avec précaution.

## Attaque basée sur le DNS
>L’empoisonnement du cache ARP cible les vulnérabilités qui se trouvent dans la résolution d’adresse sur Ethernet, l’empoisonnement du cache sur une base DNS se concentre lui sur le système de nom de domaine Internet, qui est responsable de la résolution des URL dans les adresses IP publiques. Dans ce schéma d’attaque, les hackers manipulent les entrées dans le cache d’un serveur DNS, pour les amener à répondre aux requêtes avec des adresses de destination incorrectes. Le hacker peut ainsi rediriger d’autres internautes à leur insu sur n’importe quel site Web. Pour cela, il utilise les vulnérabilités les plus connues d’anciens serveurs DNS.

>En général, les informations DNS ne sont pas stockées sur un seul serveur DNS, mais sont réparties sur plusieurs ordinateurs du réseau. Si un utilisateur souhaite accéder à un site Web, il utilise en temps normal un nom de domaine. Cependant, une adresse IP est nécessaire pour pouvoir accéder au serveur approprié. Le routeur de l’utilisateur détermine l’adresse IP en envoyant une demande DNS au serveur DNS par défaut spécifié dans la configuration. Il s’agit habituellement du serveur DNS du fournisseur d’accès à Internet. Si la liste des enregistrements DNS de l’URL requise est trouvée, alors le serveur DNS répond à la requête avec une adresse IP appropriée. Sinon, le serveur DNS détermine l’adresse IP demandée avec l’aide d’autres serveurs liés au DNS. Pour cela, il envoie une requête correspondante à d’autres serveurs DNS, et enregistre temporairement les réponses dans le cache.

>Les serveurs qui utilisent une version ancienne du logiciel DNS sont en général les victimes des attaques des hackers. Ils acceptent et stockent non seulement des informations qui ont été spécifiquement demandées, mais aussi des informations qui ont été délivrées avec elles. Si les hackers infiltrent un seul serveur DNS, il est facile d’envoyer des fausses listes avec chaque adresse IP correcte et d’empoissonner ainsi le cache du serveur DNS demandant.

>L’efficacité des attaques de « l’homme du milieu » peut être illustrée par des incidents passés où tous les espaces de noms ont été redirigés. Pour les utilisateurs, il est pratiquement impossible de se protéger, car ces attaques sont réalisées directement dans l’infrastructure du Web. Il est donc de la responsabilité de l’opérateur de s’assurer que les serveurs DNS qui sont fournis utilisent des logiciels actuels et sont suffisamment sécurisés. Par exemple, diverses normes Internet ont été élaborées sous le nom DNSSEC (Domain Name System Security Extensions), pour améliorer le système DNS avec divers mécanismes de sécurité pour renforcer l’authenticité et l’intégrité des données. Malheureusement, la distribution de ces normes prend beaucoup de temps.

## Simulation d’un point d’accès Wifi
>Un modèle d’attaque qui cible principalement les utilisateurs d’appareils mobiles est basé sur la simulation d’une connexion à un réseau Wifi public, qui peut être offert par exemple dans un café ou un aéroport. Un attaquant ou hacker configure alors son ordinateur de façon à émettre un point de connexion à Internet additionnel, et éventuellement avec une meilleure qualité du signal que le point d’accès réel. Ainsi, si un hacker parvient à tromper des utilisateurs peu méfiants, il peut alors visualiser et manipuler le trafic qui passe à travers son système avant que le trafic ne soit retransmis au point d’accès réel. Si une authentification est nécessaire, le hacker visualise et reçoit les noms d’utilisateurs et mots de passe utilisés pour se connecter. Le risque de devenir une victime de cette attaque d’« homme du milieu » est particulièrement important lorsque les appareils sont configurés pour se connecter automatiquement en priorité au point d’accès avec le signal le plus fort ou puissant.

>Là encore, la seule protection et prévention à ce type d’attaque est de se connecter uniquement aux réseaux WIFI connus. Les utilisateurs doivent s’assurer de bien utiliser le point d’accès officiel dès le début.

## Attaque « Man in the Browser »
>Une variante de l’attaque Man in the Middle, qui repose sur l’installation par un hacker de logiciels malveillants dans le navigateur d’un utilisateur d’Internet pour intercepter le trafic est connue sous le nom de l’attaque Man in the Browser (ou attaque de « l’homme dans le navigateur »). Cela touche notamment les ordinateurs qui ne sont pas régulièrement mis à jour, et qui comportent donc des vulnérabilités qui permettent aux hackers d’infiltrer facilement le système. Si des programmes spécifiques ont été introduits dans le navigateur d’un utilisateur, ils peuvent enregistrer en arrière-plan toutes les données échangées entre le système de la victime et les divers sites Web sur la Toile. Ce modèle d’attaque permet aux hackers d’intercepter un grand nombre de données avec relativement peu d’efforts. Ici, l’espionnage des données est effectué avant un éventuel chiffrement de transport via TLS/SSL.

>Le meilleur moyen pour se prémunir d’une attaque de « l’homme dans le navigateur » est de bien réaliser les mises à jour des composants logiciels du système et ainsi de combler au niveau de la sécurité les vulnérabilités et failles connues.

## Attaque « Human-Assited »
>On parle d’attaque Human-Assited lorsque l’un des schémas d’attaque décrits ci-dessus n’expire pas automatiquement, mais est au contraire contrôlé par un ou plusieurs hackers en temps réel. Dans la pratique, une attaque HDM de ce type est effectuée selon le processus suivant : dès qu’un internaute se connecte par exemple à son site de banque en ligne, le hacker qui s’est placé entre le navigateur de l’utilisateur et le serveur de la banque en ligne reçoit un signal. Il a ainsi désormais la capacité de voler les cookies de la session et les informations qui sont rédigées en temps réel lors du processus d’authentification : le hacker peut donc obtenir le nom d’utilisateur, le mot de passe et le numéro TAN par exemple.

## Prévenir les attaques de l’homme du milieu
>En règle générale, il est difficile pour les personnes concernées de reconnaître la présence d’une attaque d’homme au milieu. La meilleure protection est donc la prévention. Nous avons rassemblé ci-dessous les conseils les plus importants sur la façon dont les utilisateurs d’Internet et les exploitants de sites Web peuvent minimiser le risque de devenir la cible d’une attaque MITM.

### Conseils aux internautes :

>Veillez à toujours n’ouvrir des sites Web que via une connexion sécurisée SSL/TLS. Dans ce cas, l’adresse Internet commence par https. Les simples connexions qui ne commencent que par http constituent un risque pour la sécurité.
Vérifiez que le certificat SSL d’un site Web est bien à jour, et émis par une autorité de certification de confiance, en particulier avant de saisir vos informations d’identification.
Utilisez toujours la dernière version de votre navigateur Web préféré et actualisez régulièrement votre système d’exploitation en effectuant les mises à jour.
Évitez d’utiliser des VPN ou des serveurs proxy en accès libre.
Gardez vos mots de passe à jour, utilisez un mot de passe distinct pour chaque application et n’utilisez plus d’anciens mots de passe.
Évitez les zones wifi publiques et ouvertes, par exemple dans les hôtels, les gares ou les magasins.
Si vous ne parvenez pas à accéder aux réseaux publics, évitez les téléchargements, ne soumettez pas d’informations d’identification telles que votre compte de messagerie ou vos réseaux sociaux, et n’effectuez jamais de paiements.
Si l’opérateur d’un site Web le propose, utilisez des méthodes supplémentaires pour une connexion sécurisée, par exemple l’authentification multifactorielle (MFA) par jeton ou des mots de passe uniques par SMS ou application pour smartphone.
Ne cliquez pas sur les liens dans les emails d’expéditeurs inconnus qui pourraient vous attirer vers un site Web qui contient des logiciels malveillants.
Conseils aux administrateurs de sites Web :

>Protégez les données de vos clients en sécurisant les sites Web avec login client, en particulier avec un certificat SSL à jour d’une autorité de certification fiable.
Offrez à vos clients des méthodes supplémentaires de connexion sécurisée, comme l’authentification multifactorielle par email.
Communiquez à vos clients que vous ne leur demanderez jamais les données de connexion par email, et évitez les hyperliens dans les emails adressés aux clients.

###### © 2021 1&1 IONOS SARL
