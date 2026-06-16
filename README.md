# ft_nmap

## Usage

Build on the host machine (macOS):

```bash
make            # wrapper around CMake, produces ./ft_nmap at the project root
# or directly:
cmake -B build; cmake --build build
```

Other Makefile targets: `tests` (build the unit-test binary), `clean`, `fclean`, `re`, `help`.

### Options

| Option | Argument | Description |
| --- | --- | --- |
| `--ip` | IP or hostname | Target to scan (repeatable) |
| `--file` | path | File containing a list of targets |
| `--ports` | `22`, `22-32`, `22,80,443` | Ports to scan (default: 1-1024, max 1024 ports) |
| `--scan` | `SYN,ACK,NULL,FIN,XMAS,UDP` | Scan type(s), comma-separated (default: all) |
| `--speedup` | `0-250` | Number of threads |
| `--packet-trace` | — | Show all packets sent and received |
| `--reason` | — | Show the reason a port is in a given state |
| `--verbose` | — | Display all port states (no ignored states) |
| `--version` | — | Probe open ports to determine service/version info (bonus) |
| `--os-detect` | — | Enable OS detection (bonus) |
| `--decoy` | `ip1,ip2[,ME]` | Cloak the scan with decoy source IPs, max 3; `ME` marks where the real IP goes (bonus) |
| `--help` | — | Display usage |

Example:

```bash
sudo ./ft_nmap --ip 192.168.100.20 --ports 1-100 --scan SYN,UDP --speedup 50 --reason
```

## Docker

The Docker setup provides three containers on an isolated network (`192.168.100.0/24`):

- **source** (`192.168.100.10`) — runs ft_nmap (privileged, `NET_RAW`/`NET_ADMIN`, project mounted at `/app`)
- **target** (`192.168.100.20`) — machine to scan
- **target2** (`192.168.100.21`) — second target, identical image (useful for `--file` / multi-target scans)

The targets run real services and dummy listeners so scans return meaningful results:

- **SSH** on port 22 (`root:root`) and **nginx** on port 80
- **socat** listeners on well-known ports so the service name resolves: 21 (ftp), 23 (telnet), 25 (smtp), 53 (domain), 70 (gopher), 79 (finger), 88 (kerberos), 110 (pop3), 119 (nntp), 143 (imap), 194 (irc), 443 (https), 445 (microsoft-ds), 465 (smtps), 587 (submission), 631 (ipp), 993 (imaps), 995 (pop3s), 1194 (openvpn), 1433 (ms-sql-s), 3306 (mysql), 3389 (ms-wbt-server), 5432 (postgresql), 5900 (vnc), 6379 (redis), 6667 (irc), 8080 (http-alt), 27017 (mongod), plus 26-46

Build the images (only needed once, or after any Dockerfile change):

```bash
docker compose build
```

Start both containers:

```bash
docker compose up -d
```

Enter the **source** container:

```bash
docker exec -it ft_nmap_source bash
```

Enter the **target** containers:

```bash
docker exec -it ft_nmap_target bash
docker exec -it ft_nmap_target2 bash
```

Stop the containers:

```bash
docker compose down
```

### Building inside the container

The binary compiled on macOS won't run inside the container (different architecture). Build from inside the source container instead.

If a `build/` folder already exists from a host build, delete it first:

```bash
rm -rf build
```

Then build with sanitizers disabled (not supported on Alpine/musl):

```bash
cmake -B build -DFT_NMAP_SANITIZERS=OFF && cmake --build build
```

---

## Sniffing network traffic

Open two terminals and enter the source container in each.

**Terminal 1 — live packet capture:**

```bash
tcpdump -i eth0 -n -vv
```

**Terminal 2 — run ft_nmap against the target:**

```bash
./ft_nmap --ip 192.168.100.20 --ports 1-100
```

Save the capture as a `.pcap` file to open in Wireshark:

```bash
tcpdump -i eth0 -w /app/capture.pcap
```

The `capture.pcap` file will be available directly in the project folder.

## Testing

Build and run unit tests (greatest + pcre2):

```bash
make tests
ctest --test-dir build --output-on-failure
```

The scan suite sends raw packets and therefore requires root at runtime.

## Documentation

## Types de scan

### Protocole TCP

1 - **SCAN SYN**

-> Half scan, c'est à dire qu'on envoie une requête ``SYN`` et on attend une réponse en retour mais sans compléter la connection donc en envoyant ``RST | ACK`` si le serveur répond ``SYN | ACK`` pour éviter de se faire spam ensuite.

==Nécessite des droits sudo.==

| Probe Response                                              | Assigned State |
| ----------------------------------------------------------- | -------------- |
| TCP SYN/ACK response                                        | `open`         |
| TCP RST response                                            | `closed`       |
| No response received (even after retransmissions)           | `filtered`     |
| ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) | `filtered`     |

2 - **SCAN ACK**

Envoie une requête avec le flag ``ACK`` de set

-> Sert à déterminer si un port est filtré.

| Probe Response                                              | Assigned State |
| ----------------------------------------------------------- | -------------- |
| TCP RST response                                            | `unfiltered`   |
| No response received (even after retransmissions)           | `filtered`     |
| ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) | `filtered`     |

L'avantage du scan ``ACK`` par rapport au scan ``SYN`` est qu'il donnera un résultat de port filtré inférieur à celui du ``SYN | ACK`` qui lui est facilment filtrable car le firewall peut directement déterminé que c'est une connection entrante.
En envoyant seulement ``ACK`` le firewall est obligé de garder un état de chaque connection sortante afin d'être capable de déterminer si cette ``ACK`` fait suite à une demande de synchronisation sortante ou entrante, et renvoyer ``filtered`` dans ce dernier cas de figure.

==Nécessite des droits sudo.==

3 - **SCAN NULL, FIN, XMAS**

NULL: Envoie une requête avec aucun flags de set (-sN sur nmap)

FIN: Envoie une requête avec le flag FIN de set (-sF sur nmap)

XMAX: Envoie une requête avec les flags FIN, PSH et URG de set (-sX sur nmap)

| Probe Response                                              | Assigned State   |
| ----------------------------------------------------------- | ---------------- |
| No response received (even after retransmissions)           | `open\|filtered` |
| TCP RST packet                                              | `closed`         |
| ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) | `filtered`       |

==Nécessite des droits sudo.==

### Protocole UDP

### SCAN UDP

Envoie un datagramme UDP (vide) sur le port ciblé.

| Probe Response                                           | Assigned State   |
| -------------------------------------------------------- | ---------------- |
| Any UDP response from target port                        | `open`           |
| No response received (even after retransmissions)        | `open\|filtered` |
| ICMP port unreachable error (type 3, code 3)             | `closed`         |
| Other ICMP unreachable errors (type 3, code 1, 2, 9, 10, or 13) | `filtered` |

==Nécessite des droits sudo.==

## Types d'états de port

``filtered``: un firewall bloque la communication avec le port donc on ne peut pas dire si il est ``open`` ou ``close``

``unfiltered``: le port répond

``closed``: le port n'a pas d'application qui écoute dessus

``open``: le port n'est pas filtré et a un service qui écoute dessus

Un port ``filtered`` ne nous empêche pas de savoir le service qui tourne dessus.
