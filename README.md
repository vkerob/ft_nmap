# ft_nmap

## Usage

Build on the host machine (macOS):

```bash
cmake -B build; cmake --build build
```

## Docker

The Docker setup provides two containers on a fully isolated network:

- **source** (`192.168.100.10`) — runs ft_nmap
- **target** (`192.168.100.20`) — machine to scan (SSH open on port 22)

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

Enter the **target** container:

```bash
docker exec -it ft_nmap_target sh
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
./ft_nmap --ip 192.168.100.20 --ports 
```

Save the capture as a `.pcap` file to open in Wireshark:

```bash
tcpdump -i eth0 -w /app/capture.pcap
```

The `capture.pcap` file will be available directly in the project folder.

## Testing

Run unit tests:

```bash
ctest --test-dir build --output-on-failure
```

## Documentation

## Code source nmap

[[Analyse du code source de nmap]]

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

## Types d'états de port

``filtered``: un firewall bloque la communication avec le port donc on ne peut pas dire si il est ``open`` ou ``close``

``unfiltered``: le port répond

``closed``: le port n'a pas d'application qui écoute dessus

``open``: le port n'est pas filtré et a un service qui écoute dessus

Un port ``filtered`` ne nous empêche pas de savoir le service qui tourne dessus.
