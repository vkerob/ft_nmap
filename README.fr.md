# ft_nmap

🌐 **Français** · [English](README.md)

[![Documentation](https://img.shields.io/badge/📖_Documentation-Voir_la_page-blue?style=for-the-badge)](https://vkerob.github.io/ft_nmap/)

Réimplémentation d'un scanner de ports inspiré de `nmap`, écrite en C.
Le programme envoie des paquets bruts (raw sockets) et capture les réponses
avec `libpcap` pour déterminer l'état de chaque port d'une ou plusieurs cibles.

Six techniques de scan sont disponibles : **SYN, ACK, NULL, FIN, XMAS** (TCP)
et **UDP**. Plusieurs techniques peuvent être combinées dans une même exécution.

> ⚠️ Le scan envoie des paquets bruts : **les droits root sont requis à
> l'exécution** (`sudo`), sauf pour `--help`.

---

## Sommaire

- [Compilation](#compilation)
- [Docker](#docker)
- [Utilisation](#utilisation)
- [Différences avec le vrai nmap](#différences-avec-le-vrai-nmap)
- [États des ports et signification des réponses](#états-des-ports-et-signification-des-réponses)
- [Architecture : libpcap et netfilter dans le noyau](#architecture--libpcap-et-netfilter-dans-le-noyau)
- [Tests](#tests)

---

## Compilation

Le vrai système de build est **CMake**. Le `Makefile` est un simple wrapper
au-dessus de CMake (le sujet impose la présence d'un Makefile) qui délègue
tout à `cmake`.

Dans tous les cas, le binaire final `ft_nmap` est produit **à la racine du
projet** (CMake le place là via `RUNTIME_OUTPUT_DIRECTORY`).

### 1. Avec le Makefile (recommandé)

```bash
make            # configure + build -> ./ft_nmap
```

Cibles disponibles :

| Cible | Effet |
| --- | --- |
| `make` / `make all` | Construit `ft_nmap` (cible par défaut) |
| `make tests` | Construit le binaire de tests unitaires `tests_ft_nmap` |
| `make clean` | Supprime le dossier `build/` |
| `make fclean` | `clean` + supprime le binaire `ft_nmap` |
| `make re` | `fclean` + `all` |
| `make help` | Affiche la liste des cibles |

### 2. Directement avec CMake

```bash
cmake -B build              # configuration (à refaire seulement si CMakeLists change)
cmake --build build         # compilation
```

### 3. Option de compilation : sanitizers

Les sanitizers ASan/UBSan sont **activés par défaut** (utile pour le debug
mémoire). Pour les désactiver — **obligatoire sur Alpine/musl**, c'est-à-dire
dans le conteneur Docker, où ils ne sont pas supportés :

```bash
cmake -B build -DFT_NMAP_SANITIZERS=OFF
cmake --build build
```

On peut passer cette option au Makefile via `CMAKE_GEN_FLAGS` :

```bash
make CMAKE_GEN_FLAGS=-DFT_NMAP_SANITIZERS=OFF
```

---

## Docker

L'environnement Docker monte trois conteneurs sur un réseau isolé
(`192.168.100.0/24`), ce qui permet de scanner des cibles réalistes sans
toucher à une vraie machine du réseau.

| Conteneur | IP | Rôle |
| --- | --- | --- |
| `ft_nmap_source` | `192.168.100.10` | Lance `ft_nmap` (privilégié, `NET_RAW`/`NET_ADMIN`, projet monté dans `/app`) |
| `ft_nmap_target` | `192.168.100.20` | Cible à scanner |
| `ft_nmap_target2` | `192.168.100.21` | Seconde cible identique (utile pour `--file` / multi-cibles) |

Les cibles font tourner de vrais services et des écouteurs factices pour que
les scans renvoient des résultats parlants :

- **SSH** sur le port 22 (`root:root`) et **nginx** sur le port 80
- des écouteurs **socat** sur des ports bien connus pour que le nom de service
  se résolve : 21 (ftp), 23 (telnet), 25 (smtp), 53 (domain), 110 (pop3),
  143 (imap), 443 (https), 445 (microsoft-ds), 3306 (mysql), 5432 (postgresql),
  6379 (redis), 8080 (http-alt), 27017 (mongod), etc.

### Cycle de vie des conteneurs

Construire les images (une seule fois, ou après modification d'un Dockerfile) :

```bash
docker compose build
```

Démarrer les conteneurs :

```bash
docker compose up -d
```

Entrer dans le conteneur **source** (d'où on lance les scans) :

```bash
docker exec -it ft_nmap_source bash
```

Entrer dans une **cible** (pour inspecter, sniffer, etc.) :

```bash
docker exec -it ft_nmap_target bash
docker exec -it ft_nmap_target2 bash
```

Arrêter et supprimer les conteneurs :

```bash
docker compose down
```

### Compiler à l'intérieur du conteneur

Un binaire compilé sur la machine hôte **ne tournera pas forcément** dans le
conteneur : l'environnement (architecture, bibliothèques, libc) peut différer.
Il faut donc recompiler depuis le conteneur source.

Si un dossier `build/` issu d'un build hôte existe déjà, le supprimer d'abord :

```bash
rm -rf build
```

Puis compiler **avec les sanitizers désactivés** (non supportés sur
Alpine/musl) :

```bash
cmake -B build -DFT_NMAP_SANITIZERS=OFF && cmake --build build
```

### Sniffer le trafic réseau

#### Pourquoi passer par `tcpdump` (et pas Wireshark en direct)

Les conteneurs tournent sur un **réseau bridge isolé interne à Docker**
(`192.168.100.0/24`). Le trafic des scans circule donc sur une interface qui
vit *à l'intérieur* de Docker, pas sur la machine hôte.

Sur macOS et Windows, Docker s'exécute dans une VM Linux : l'interface où passe
réellement ce trafic **n'est pas visible** depuis le Wireshark de la machine
hôte. Sélectionner une interface dans Wireshark ne montrera donc rien. (Sur un
hôte Linux natif, le bridge `br-xxxx` apparaît et Wireshark pourrait écouter
dessus — mais ce n'est pas portable d'un poste à l'autre.)

La méthode fiable, qui marche partout, est donc de **capturer avec `tcpdump`
depuis le conteneur** (qui, lui, est bien sur le réseau `192.168.100.0/24` via
son interface `eth0`), d'écrire un fichier `.pcap` dans le volume monté `/app`,
puis d'**ouvrir ce `.pcap` dans Wireshark** sur la machine hôte.

#### Regarder en direct dans le terminal

Ouvrir deux terminaux dans le conteneur source.

**Terminal 1 — capture en direct :**

```bash
tcpdump -i eth0 -n -vv
```

**Terminal 2 — lancer un scan :**

```bash
./ft_nmap --ip 192.168.100.20 --ports 1-100
```

#### Analyser dans Wireshark

Capturer dans un fichier `.pcap` (Ctrl-C pour arrêter), pendant qu'un scan
tourne dans un autre terminal :

```bash
tcpdump -i eth0 -n -w /app/capture.pcap
```

Comme `/app` est le dossier du projet monté en volume, le fichier
`capture.pcap` apparaît directement dans le dossier `ft_nmap` sur la machine
hôte : il suffit de l'ouvrir dans Wireshark.

### Banc de test : reproduire chaque état

Chaque technique de scan a un **ensemble fini d'états possibles**, et ils sont
**tous reproductibles** sur les cibles, à une exception près : l'état UDP
`open` (voir [Note UDP : pourquoi `open` n'est jamais
rapporté](#note-udp--pourquoi-open-nest-jamais-rapporté)). Les ports ci-dessous
sont **pré-configurés automatiquement** au démarrage du conteneur cible
(écouteurs + règles `iptables` posés dans le `CMD` de `Dockerfile.target` ; les
règles netfilter vivent dans le noyau et ne peuvent pas persister via un
`RUN`).

États possibles par technique :

- **SYN** : `open`, `closed`, `filtered`
- **ACK** : `unfiltered`, `filtered`
- **NULL / FIN / XMAS** : `open|filtered`, `closed`, `filtered`
- **UDP** : `open|filtered`, `closed`, `filtered` (`open` est implémenté mais
  hors d'atteinte avec une sonde sans charge utile, voir la note plus bas)

#### Ports du banc et états attendus

| Port | Configuration sur la cible | Scan à lancer | État attendu |
| --- | --- | --- | --- |
| `4300` | écouteur TCP | `SYN` | `open` |
| `4300` | écouteur TCP | `NULL`/`FIN`/`XMAS` | `open\|filtered` |
| `4300` | écouteur TCP | `ACK` | `unfiltered` |
| `4301` | libre (aucun service, aucune règle) | `SYN` | `closed` |
| `4301` | libre | `NULL`/`FIN`/`XMAS` | `closed` |
| `4302` | `iptables --syn -j DROP` (sans état) | `SYN` | `filtered` |
| `4302` | `iptables --syn -j DROP` | `ACK` | `unfiltered` |
| `4303` | `iptables --ctstate NEW,INVALID -j DROP` (à état) | `SYN` | `filtered` |
| `4303` | `iptables --ctstate NEW,INVALID -j DROP` | `ACK` | `filtered` |
| `4304` | `iptables -j REJECT --reject-with icmp-host-prohibited` | `SYN`/`ACK`/`NULL`/`FIN`/`XMAS` | `filtered` |
| `4310` | écho UDP (ne répond qu'à un datagramme porteur d'une charge utile) | `UDP` | `open\|filtered` |
| `4311` | libre (aucun service, aucune règle) | `UDP` | `closed` |
| `4312` | `iptables -p udp -j DROP` | `UDP` | `open\|filtered` |
| `4313` | `iptables -p udp -j REJECT --reject-with icmp-host-prohibited` | `UDP` | `filtered` |

> Le port `4310` fait bien tourner un service d'écho UDP, et il est pourtant
> rapporté `open|filtered` et non `open` : notre sonde ne porte aucune charge
> utile, le service n'a donc rien à renvoyer. Voir
> [Note UDP : pourquoi `open` n'est jamais rapporté](#note-udp--pourquoi-open-nest-jamais-rapporté).

#### Lancer le banc

Depuis le conteneur source. Tous les scans TCP sur les ports TCP du banc :

```bash
./ft_nmap --ip 192.168.100.20 --ports 4300,4301,4302,4303,4304 \
          --scan SYN,ACK,NULL,FIN,XMAS --reason --verbose
```

Le scan UDP sur les ports UDP du banc :

```bash
./ft_nmap --ip 192.168.100.20 --ports 4310,4311,4312,4313 \
          --scan UDP --reason --verbose
```

`--verbose` force l'affichage de tous les ports (rien n'est regroupé dans
« Not shown »), et `--reason` montre la cause de chaque état.

#### Les types de filtrage

`filtered` ne recouvre pas une seule réalité. Ce que le pare-feu *fait*
réellement de la sonde détermine **comment** (et à quelle vitesse) ft_nmap le
détecte, ainsi que la raison rapportée. Deux axes indépendants.

**1. Ce que le pare-feu fait du paquet**

| Règle du pare-feu | Ce qui revient | Résultat ft_nmap | Raison affichée |
| --- | --- | --- | --- |
| `-j DROP` (trou noir silencieux) | rien du tout | `filtered`, mais seulement une fois les retries + le timeout épuisés | `no-response` |
| `-j REJECT --reject-with icmp-*` | une erreur **ICMP** *destination unreachable* | `filtered`, immédiatement | le code ICMP exact : `admin-prohib`, `host-prohib`, `net-unreach`, `port-unreach`, … |
| `-j REJECT --reject-with tcp-reset` | un **`RST`** TCP (identique à un vrai port fermé) | `closed` — et **non** `filtered` | `reset` |

À retenir :

- Un **`DROP`** silencieux est le plus lent à détecter : aucune réponse, on ne
  peut conclure `filtered` qu'après avoir attendu chaque retry (voir
  [Timeout et retries](#timeout-et-retries) ; ports `4302`/`4303` en `SYN`, `4312` en UDP).
- Un **`REJECT`** ICMP est le plus rapide et le plus informatif : le *code* ICMP
  nous dit *pourquoi* la sonde a été bloquée. C'est exactement ce que
  `icmp_code_to_reason()` décode dans la colonne raison (ports `4304`, `4313`).
- Un **`REJECT` tcp-reset** permet au pare-feu de **déguiser** un port filtré en
  port fermé : un `RST` forgé est indiscernable du `RST` d'un port fermé.

**2. Sans état vs à état**

Ce second axe est orthogonal au premier : il détermine si un `ACK` *isolé*
franchit le filtre, et il est détaillé dans la section suivante.

#### Le cas SYN vs ACK (sans état / à état)

Les ports `4302` et `4303` illustrent la complémentarité SYN/ACK (cf. la
section [scan ACK](#tcp--ack-scan---scan-ack)) :

- `4302` (pare-feu **sans état**, bloque seulement les `SYN`) → `SYN(filtered)`
  mais `ACK(unfiltered)` : l'`ACK` isolé passe et révèle que le filtrage ne
  vise que les nouvelles connexions.
- `4303` (pare-feu **à état**) → `SYN(filtered)` **et** `ACK(filtered)` : le
  `SYN` (NEW) comme l'`ACK` isolé (INVALID) sont jetés.

#### Note UDP : pourquoi `open` n'est jamais rapporté

ft_nmap envoie un datagramme UDP **vide** (en-tête seul, sans charge utile).
Quasiment aucun service ne répond à une telle sonde : DNS, SNMP ou NTP ne
répondent qu'à une requête bien formée de leur propre protocole, et même un
écouteur d'écho générique n'a rien à renvoyer lorsqu'il reçoit zéro octet. Un
port UDP ouvert reste donc muet, et ft_nmap le rapporte en `open|filtered` —
exactement comme un port derrière une règle `DROP`.

L'état `open` reste implémenté : il est rapporté (avec la raison
`udp-response`) dès qu'un datagramme revient du port cible. Mais le banc ne
peut pas produire ce cas — le port `4310` ne répond pas à une sonde sans charge
utile — donc `open` est le seul état de la matrice qui n'est **pas
reproductible** ici. Le rapporter de façon fiable demanderait des charges
utiles spécifiques par protocole (une requête DNS pour le `53`, un SNMP get
pour le `161`…), comme le fait `nmap` avec son fichier `nmap-payloads`.

#### Note UDP : limitation ICMP du noyau

Les états UDP `closed` et `filtered` reposent sur des **erreurs ICMP** générées
par le noyau de la cible. Or le noyau **limite le débit d'erreurs ICMP** (de
l'ordre de 5/seconde). En scannant beaucoup de ports UDP d'un coup, certains
ports `closed` peuvent donc apparaître à tort en `open|filtered` (l'ICMP a été
étranglé). Le banc ne contient que 4 ports UDP, donc on reste sous la limite ;
pour scanner de larges plages UDP, il faut ralentir l'envoi (throttling).

---

## Utilisation

```
sudo ./ft_nmap [options] (--ip <cible> | --file <fichier>)
```

### Options

| Option | Argument | Description |
| --- | --- | --- |
| `--ip` | IP ou hostname | Cible à scanner (répétable) |
| `--file` | chemin | Fichier contenant une liste de cibles (une par ligne) |
| `--ports` | `22`, `22-32`, `22,80,443` | Ports à scanner (défaut : `1-1024`, **max 1024 ports**) |
| `--scan` | `SYN,ACK,NULL,FIN,XMAS,UDP` | Type(s) de scan, séparés par des virgules (défaut : tous) |
| `--speedup` | `0-250` | Nombre de threads |
| `--timeout` | `0-10000` (ms) | Temps d'attente d'une réponse avant de considérer une sonde comme perdue (défaut : `1000`) (bonus) |
| `--max-retries` | `0-5` | Nombre maximum d'envois d'une sonde avant d'abandonner (défaut : `3`) (bonus) |
| `--packet-trace` | — | Affiche tous les paquets envoyés et reçus (bonus) |
| `--reason` | — | Affiche la raison de l'état d'un port (bonus) |
| `--verbose` | — | Affiche tous les états de port (aucun état ignoré) (bonus) |
| `--decoy` | `ip1,ip2[,ME]` | Camoufle le scan avec des IP source leurres, max 3 ; `ME` marque où va la vraie IP (bonus) |
| `--traceroute` | — | Trace la route vers chaque cible après le scan, avec des sondes UDP (bonus) |
| `--traceroute-icmp` | — | Idem, avec des sondes ICMP echo ; combinée à `--traceroute`, chaque hop est sondé avec les deux (bonus) |
| `--help` | — | Affiche l'aide |

> **Root requis.** Chaque type de scan forge ses propres paquets sur des raw
> sockets et libpcap doit ouvrir l'interface : ft_nmap refuse de démarrer s'il
> n'est pas lancé en root. `--help` reste accessible sans privilèges.

> **Obligatoire vs bonus.** Seules `--help`, `--ip`, `--file`, `--ports`,
> `--scan` et `--speedup` font partie de la partie obligatoire du sujet. Toutes
> les options marquées *(bonus)* sont des « additional flags » optionnels.
> Remarque : le sujet précise que le flag de verbosité `-v/-V` n'est pas
> considéré comme un bonus valide en soi.

### Lancer sans option

Avec uniquement une cible, ft_nmap utilise les valeurs par défaut : **ports
1-1024** et **tous les types de scan** (SYN, ACK, NULL, FIN, XMAS, UDP).

```bash
sudo ./ft_nmap --ip 192.168.100.20
```

### Lancer avec des options

Un seul type de scan, une plage de ports, en montrant la raison de l'état :

```bash
sudo ./ft_nmap --ip 192.168.100.20 --ports 1-100 --scan SYN --reason
```

Plusieurs cibles, ou une liste depuis un fichier :

```bash
sudo ./ft_nmap --ip 192.168.100.20 --ip 192.168.100.21 --scan SYN
sudo ./ft_nmap --file targets.txt --ports 22,80,443
```

Accélérer avec plusieurs threads :

```bash
sudo ./ft_nmap --ip 192.168.100.20 --ports 1-1024 --speedup 50 --scan SYN
```

### Timeout et retries

Quand une sonde reste sans réponse, ft_nmap attend `--timeout` millisecondes,
puis la renvoie. Une fois la sonde envoyée `--max-retries` fois sans aucune
réponse, ft_nmap abandonne et donne au port l'état `filtered` ou `open|filtered`
en fonction du type de scan, avec la raison `no-response` :

| Type de scan | État quand rien ne revient |
| --- | --- |
| `SYN`, `ACK` | `filtered` |
| `NULL`, `FIN`, `XMAS`, `UDP` | `open\|filtered` |

| Option | Plage | Défaut | Remarques |
| --- | --- | --- | --- |
| `--timeout` | `0`–`10000` | `1000` | Toujours en **millisecondes**, sans unité (`500`, pas `500ms`). Les décimales sont acceptées (`250.5`). |
| `--max-retries` | `0`–`5` | `3` | Compte les **envois**, pas les renvois : `3` = la sonde d'origine + 2 renvois. `0` et `1` donnent tous les deux un seul envoi. |

Un port qui ne répond jamais coûte donc environ `max-retries × timeout`
(3 × 1 s = **3 s** avec les valeurs par défaut). Les ports qui répondent, y
compris par une erreur ICMP, sont résolus dès l'arrivée de la réponse : ces
options ne changent que la durée de traitement des ports *silencieux* (par
exemple derrière une règle `DROP`, voir [Les types de filtrage](#les-types-de-filtrage)).

Scan rapide d'un réseau local, avec moins de patience pour les ports silencieux :

```bash
sudo ./ft_nmap --ip 192.168.100.20 --scan SYN --timeout 200 --max-retries 1
```

Lien lent ou avec des pertes, où les réponses peuvent arriver en retard ou se perdre :

```bash
sudo ./ft_nmap --ip 192.168.100.20 --scan UDP --timeout 3000 --max-retries 5
```

Les valeurs hors plage, négatives, avec un signe `+` explicite ou suivies
d'autres caractères sont refusées avec une erreur.

### Combiner plusieurs scans TCP (et UDP)

ft_nmap peut exécuter **plusieurs techniques dans la même exécution**. Les
résultats de chaque technique sont fusionnés en un état final par port (voir
la section différences ci-dessous), et une colonne `SCAN RESULTS` détaille le
résultat de chaque technique :

```bash
sudo ./ft_nmap --ip 192.168.100.20 --ports 20-25 --scan SYN,ACK,NULL --reason
```

Exemple de sortie (multi-scan) :

```
Starting ft_nmap at 2026-06-16 08:36 +0200
Nmap scan report for target (192.168.100.20)
Host is up.
PORT      STATE          SERVICE              SCAN RESULTS              REASON
22/tcp    open           ssh                  SYN(open) ACK(unfiltered) NULL(open|filtered)    syn-ack
23/tcp    closed         telnet               SYN(closed) ACK(unfiltered) NULL(closed)         reset

ft_nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
```

Exemple de sortie (scan simple) :

```
Starting ft_nmap at 2026-06-16 08:36 +0200
Nmap scan report for target (192.168.100.20)
Host is up.
PORT      STATE          SERVICE
22/tcp    open           ssh
80/tcp    open           http

ft_nmap done: 1 IP address (1 host up) scanned in 0.21 seconds
```

> Quand un état regroupe plus de 25 ports, ils ne sont pas listés un par un :
> une ligne `Not shown: N closed tcp ports (reset)` les résume. Utiliser
> `--verbose` pour forcer l'affichage de tous les ports.

---

### Traceroute

`--traceroute` trace la route vers chaque cible une fois son scan terminé, et
affiche le résultat juste sous son tableau de ports :

```bash
sudo ./ft_nmap --ip scanme.nmap.org --ports 22 --scan SYN --traceroute
```

```
TRACEROUTE (using UDP ports 33434-33457)
HOP RTT       ADDRESS
1   0.62 ms   192.168.1.1
2   8.30 ms   10.0.0.1, 10.0.0.2
3   ... 6
7   24.55 ms  62.115.120.1
8   31.02 ms  scanme.nmap.org (45.33.32.156)
```

Trois sondes sont envoyées par hop. La colonne `RTT` affiche la meilleure, et un
hop auquel plusieurs routeurs répondent (répartition de charge) liste toutes les
adresses. Les hops muets consécutifs sont regroupés sur une ligne : `3   ... 6`
signifie que les hops 3 à 6 n'ont pas répondu.

`--traceroute-icmp` envoie des ICMP echo request au lieu de datagrammes UDP, ce
qui passe là où un pare-feu jette l'UDP vers les ports hauts. Passer les **deux**
options sonde chaque hop avec les deux types et garde la première réponse : deux
fois plus de paquets, mais un type filtré n'aveugle plus toute la trace.

Les hops intermédiaires sont affichés en adresses IP. Les résoudre bloquerait
plusieurs secondes sur chaque routeur sans enregistrement `PTR`, donc seule la
destination affiche un nom, repris du reverse DNS déjà fait par le scan.

---

## Différences avec le vrai nmap

ft_nmap reproduit le comportement de nmap, avec quelques particularités
propres au projet :

1. **État final combiné + état `unknown`.** Quand plusieurs types de scan sont
   lancés ensemble, ft_nmap fusionne leurs résultats en un seul état
   « définitif » par port. Si deux techniques se contredisent, le port est
   marqué `unknown`. Le vrai nmap ne fait pas cette fusion et n'a pas cet état.

   Ce cas est rare mais possible. Exemple concret : un scan SYN renvoie `open`
   (le port répond `SYN/ACK`) tandis qu'un scan NULL/FIN/XMAS renvoie `closed`
   (le port répond `RST`). Cela arrive contre des piles réseau qui répondent
   `RST` à *toutes* les sondes — typiquement Windows — au lieu de respecter le
   comportement attendu où un port ouvert ne répond pas aux scans NULL/FIN/XMAS
   (`open|filtered`). Sur une cible « classique » (Linux, etc.), les techniques
   s'accordent et `unknown` n'apparaît pas.

2. **Colonne `SCAN RESULTS`.** En mode multi-scan, ft_nmap ajoute une colonne
   qui montre le résultat de *chaque* technique pour chaque port (par ex.
   `SYN(open) ACK(unfiltered)`), en plus de l'état combiné de la colonne
   `STATE`.

3. **Limites propres au projet :**
   - au maximum **1024 ports** par exécution ;
   - au maximum **250 threads** (`--speedup`) ;
   - au maximum **3 leurres** (`--decoy`, bonus) ;
   - plage de ports par défaut **1-1024** ;
   - **IPv4 uniquement**.

4. **`--traceroute` (bonus) : marche avant classique.** ft_nmap parcourt les
   TTL 1, 2, 3… comme `traceroute(8)`, en envoyant des datagrammes UDP vers des
   ports hauts inutilisés (33434 et suivants) pour que la destination réponde
   `ICMP port unreachable`. Le vrai nmap procède à l'envers : il déduit la
   distance de la cible du TTL des paquets reçus pendant le scan, puis sonde à
   rebours depuis cette distance en réutilisant un port qu'il a trouvé ouvert.
   Deux conséquences en pratique : ft_nmap envoie plus de sondes, et il affiche
   des hops que nmap masque (l'endpoint d'un VPN sur le chemin, par exemple).
   ft_nmap emprunte une idée à nmap : quand le scan a capturé une réponse de la
   cible, son TTL borne le nombre de hops à parcourir au lieu des 30 par
   défaut.

---

## États des ports et signification des réponses

### Les états possibles

| État | Signification |
| --- | --- |
| `open` | Le port n'est pas filtré et un service écoute dessus. |
| `closed` | Le port est joignable mais aucune application n'écoute dessus. |
| `filtered` | Un pare-feu bloque la communication : impossible de dire si le port est `open` ou `closed`. |
| `unfiltered` | Le port est joignable (il répond), mais on ne peut pas déterminer s'il est `open` ou `closed` (réponse du scan ACK). |
| `open\|filtered` | Le port est soit ouvert, soit filtré ; le scan ne permet pas de trancher (NULL/FIN/XMAS et UDP). |
| `unknown` | Spécifique à ft_nmap : plusieurs techniques ont donné des résultats contradictoires sur ce port. |

> Un port `filtered` n'empêche pas forcément de connaître le service censé y
> tourner : le nom affiché vient du numéro de port (table `nmap-services`).

### Réponses obtenues selon la technique de scan

#### TCP — SYN scan (`--scan SYN`)

Half-open scan : on envoie un `SYN` et on attend la réponse, sans compléter la
connexion (on envoie un `RST` si le serveur répond `SYN/ACK`).

| État obtenu | …parce qu'on a reçu |
| --- | --- |
| `open` | un paquet TCP avec les flags **`SYN` + `ACK`** positionnés |
| `closed` | un paquet TCP avec le flag **`RST`** (avec ou sans `ACK`) |
| `filtered` | **aucune réponse** (même après retransmission), **ou** une erreur ICMP *unreachable* (type 3, code 0, 1, 2, 3, 9, 10 ou 13) |

> **Pourquoi SYN ?** C'est le scan de référence : le plus précis pour savoir ce
> qui est *ouvert*, car il distingue clairement `open` / `closed` / `filtered`.
> Comme on ne termine jamais la connexion (on coupe avec un `RST` après le
> `SYN/ACK`), il est rapide et laisse moins de traces qu'une vraie connexion
> complète. C'est le point de départ logique de tout scan ; les autres
> techniques servent à compléter ce qu'il ne peut pas voir (pare-feu, UDP,
> évasion).

#### TCP — ACK scan (`--scan ACK`)

Envoie un paquet avec uniquement le flag `ACK`. Sert à déterminer si un port
est filtré (et donc à cartographier les règles de pare-feu).

| État obtenu | …parce qu'on a reçu |
| --- | --- |
| `unfiltered` | un paquet TCP avec le flag **`RST`** |
| `filtered` | **aucune réponse** (même après retransmission), **ou** une erreur ICMP *unreachable* (type 3, code 0, 1, 2, 3, 9, 10 ou 13) |

> **Pourquoi ACK en plus de SYN ?** Le SYN dit ce qui est *ouvert* ; l'ACK ne
> le dit jamais (un port `open` comme `closed` renvoient un `RST` →
> `unfiltered`). L'ACK sert à sonder le **pare-feu** : un port `filtered` au SYN
> qui ressort `unfiltered` à l'ACK révèle un pare-feu *sans état*, qui ne bloque
> que les nouvelles connexions (`SYN`) ; s'il reste `filtered`, le pare-feu est
> *à état* et bloque aussi les ACK isolés. Les deux scans sont complémentaires :
> SYN = quels ports sont ouverts, ACK = comment le pare-feu est configuré.

#### TCP — NULL / FIN / XMAS (`--scan NULL,FIN,XMAS`)

- **NULL** : aucun flag positionné (`-sN` sur nmap).
- **FIN** : seul le flag `FIN` positionné (`-sF` sur nmap).
- **XMAS** : flags `FIN`, `PSH` et `URG` positionnés (`-sX` sur nmap).

| État obtenu | …parce qu'on a reçu |
| --- | --- |
| `open\|filtered` | **aucune réponse** (même après retransmission) — un port ouvert ignore la sonde |
| `closed` | un paquet TCP avec le flag **`RST`** |
| `filtered` | une erreur ICMP *unreachable* (type 3, code 0, 1, 2, 3, 9, 10 ou 13) |

> **Pourquoi NULL / FIN / XMAS ?** Ces scans exploitent la RFC 793 : un port
> *fermé* doit répondre `RST` à tout paquet sans `SYN`/`RST`/`ACK`, alors qu'un
> port *ouvert* doit l'ignorer (pas de réponse). D'où l'absence de réponse =
> `open|filtered` et le `RST` = `closed`. Deux intérêts par rapport au SYN :
> **discrétion** (pas de `SYN`, donc ils échappent souvent aux IDS et aux logs
> qui guettent les débuts de connexion) et **évasion** des pare-feux *sans
> état* qui ne filtrent que les `SYN`. Grosse limite : ça ne marche que contre
> des piles réseau qui respectent la RFC (beaucoup d'Unix) ; Windows, certains
> équipements Cisco, etc. répondent `RST` à tout → tous les ports paraissent
> `closed`. Les trois variantes (aucun flag / `FIN` / `FIN`+`PSH`+`URG`) sont
> équivalentes côté logique ; elles diffèrent juste par les flags, ce qui
> permet de contourner un filtre qui repérerait une combinaison mais pas une
> autre.

#### UDP scan (`--scan UDP`)

Envoie un datagramme UDP **sans charge utile** (en-tête seul) sur le port ciblé.

| État obtenu | …parce qu'on a reçu |
| --- | --- |
| `open` | n'importe quel **datagramme UDP** renvoyé par le port cible — implémenté, mais en pratique rien ne répond à une sonde sans charge utile, donc cet état n'est jamais rapporté ([pourquoi](#note-udp--pourquoi-open-nest-jamais-rapporté)) |
| `open\|filtered` | **aucune réponse** (même après retransmission) |
| `closed` | une erreur ICMP **port unreachable** (type 3, code 3) |
| `filtered` | une autre erreur ICMP *unreachable* (type 3, code 0, 1, 2, 9, 10 ou 13) |

> **Pourquoi UDP ?** Les scans précédents ne voient que le TCP, or beaucoup de
> services critiques tournent en **UDP** : DNS (53), SNMP (161), DHCP (67/68),
> NTP (123)... Sans scan UDP, ces services sont totalement invisibles. La
> contrepartie : l'UDP n'a pas de poignée de main, donc la détection est plus
> lente et moins fiable. Un port ouvert ne répond généralement rien (d'où
> `open|filtered`), et seul un ICMP *port unreachable* permet d'affirmer qu'un
> port est `closed`. C'est le scan à utiliser dès qu'on veut une image complète
> de la cible, pas seulement sa surface TCP.

---

## Architecture : libpcap et netfilter dans le noyau

Pour comprendre *comment* ft_nmap envoie ses sondes et récupère les réponses —
et pourquoi un pare-feu donne les états vus plus haut — il faut regarder le
trajet d'un paquet **à l'intérieur du noyau**.

![Trajet d'un paquet entrant dans le noyau : capture (BPF/libpcap) d'un côté, IP routing + netfilter de l'autre, et les types de datalink côté capture](docs/kernel-packet-flow.png)

*(Version PDF haute résolution : [`docs/kernel-packet-flow.pdf`](docs/kernel-packet-flow.pdf).)*

### Le paquet entrant se dédouble

Quand un paquet TCP arrive sur l'interface (`eth0`), le noyau l'envoie sur
**deux branches indépendantes** :

1. **Packet capture (libpcap).** Un programme **BPF** filtre les paquets,
   remplit un buffer, et l'espace utilisateur le lit via un *pcap handle*.
   C'est ce que font `tcpdump` **et ft_nmap** pour lire les réponses aux
   sondes.
2. **IP Routing + Netfilter.** Le chemin « normal » du paquet : le noyau le
   route (`Local` s'il nous est destiné) puis le soumet aux règles netfilter,
   qui décident `continue` (→ `send to socket` : raw, TCP, UDP, ICMP) ou
   `drop`/`STOP`.

### Le point clé : la capture se fait *avant* netfilter

Pour le trafic **entrant**, le tap BPF a lieu **avant** que netfilter ne
statue. Conséquence directe : **libpcap voit même les paquets que netfilter va
jeter ensuite.** C'est pourquoi `tcpdump` peut afficher un paquet qu'une règle
`iptables -j DROP` élimine juste après — les deux mécanismes vivent dans le
noyau, mais à des étages différents.

### Où ft_nmap se place

ft_nmap utilise les deux extrémités du schéma, côté *user/dev space* :

- **`socket raw`** pour **forger et envoyer** ses sondes (SYN, ACK, datagrammes
  UDP…) avec ses propres en-têtes.
- **`pcap handle`** pour **capturer les réponses** (`SYN/ACK`, `RST`, erreurs
  ICMP) via la branche packet capture, indépendamment des sockets classiques.

### Les types de datalink (panneau `datalink_type`)

Quand libpcap te livre un paquet, celui-ci ne commence **pas toujours au même
endroit** : selon l'interface capturée, la trame est précédée d'un en-tête de
couche liaison différent. libpcap indique lequel via `pcap_datalink()`, et
ft_nmap s'en sert pour calculer **où débute l'en-tête IP** avant de parser la
réponse. Les cas gérés par ft_nmap :

| Datalink type | En-tête avant l'IP | Cas typique |
| --- | --- | --- |
| `DLT_EN10MB` | en-tête **Ethernet** (14 octets) | interface Ethernet classique (`eth0`) ; loopback Linux |
| `DLT_NULL` | en-tête **loopback BSD** (4 octets : famille d'adresse) | loopback sur BSD/macOS, p. ex. `127.0.0.1` sous macOS |
| `DLT_RAW` | **aucun** : la trame commence directement à l'IP | interfaces point-à-point / tunnels |

Concrètement, ft_nmap regarde le type de datalink, **retire l'en-tête de
liaison correspondant** (rien pour `DLT_RAW`), puis lit l'en-tête IP suivi de
l'en-tête TCP/UDP/ICMP. C'est ce qui lui permet d'analyser les réponses quelle
que soit l'interface, sans supposer qu'il y a toujours un en-tête Ethernet.

> Le schéma montre aussi **`DLT_LINUX_SLL`** (en-tête « cooked » `sll_header`).
> ft_nmap ne le gère **pas volontairement** : ce type n'apparaît que lorsqu'on
> capture sur l'interface spéciale `any`, que le projet ne sélectionne jamais
> par défaut — il choisit toujours l'interface réelle menant à la cible.

### netfilter / iptables, concrètement

Le pare-feu de Linux, c'est le framework **netfilter** intégré au noyau.
`iptables` n'est que l'outil en espace utilisateur qui lui installe des règles ;
c'est le noyau qui les applique. Les règles sont rangées en **chaînes** selon
le trajet du paquet : `INPUT` (destiné à la machine), `OUTPUT` (émis par elle),
`FORWARD` (en transit). Chaque règle est une **condition** (protocole, port,
flags TCP, état de connexion…) suivie d'une **cible** (`ACCEPT`, `DROP`,
`REJECT`…) ; le noyau parcourt la chaîne et la **première règle qui matche**
décide.

Le lien avec les états de port : une cible `DROP` jette le paquet **sans rien
renvoyer**. Côté scanner, « aucune réponse » → `filtered`. Et le module
**conntrack** du noyau, qui mémorise l'état de chaque connexion
(`NEW`, `ESTABLISHED`, `INVALID`…), est ce qui permet un pare-feu **à état** :
c'est lui qui reconnaît qu'un `ACK` isolé ne correspond à aucune connexion
établie (`INVALID`) et le jette — voir le
[banc de test](#banc-de-test--reproduire-chaque-état).

---

## Tests

Construire et lancer les tests unitaires (greatest + pcre2) :

```bash
make tests
ctest --test-dir build --output-on-failure
```

La suite de scan envoie des paquets bruts : elle **nécessite root** à
l'exécution.
