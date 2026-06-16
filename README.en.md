# ft_nmap

🌐 [Français](README.fr.md) · **English**

A C reimplementation of a `nmap`-inspired port scanner. The program sends raw
packets (raw sockets) and captures the replies with `libpcap` to determine the
state of each port on one or more targets.

Six scan techniques are available: **SYN, ACK, NULL, FIN, XMAS** (TCP) and
**UDP**. Several techniques can be combined in a single run.

> ⚠️ The scan sends raw packets: **root privileges are required at runtime**
> (`sudo`), except for `--help`.

---

## Table of contents

- [Building](#building)
- [Docker](#docker)
- [Usage](#usage)
- [Differences from real nmap](#differences-from-real-nmap)
- [Port states and what the responses mean](#port-states-and-what-the-responses-mean)
- [Architecture: libpcap and netfilter in the kernel](#architecture-libpcap-and-netfilter-in-the-kernel)
- [Tests](#tests)

---

## Building

The real build system is **CMake**. The `Makefile` is a thin wrapper around
CMake (the subject requires a Makefile) that delegates everything to `cmake`.

In every case the final `ft_nmap` binary is produced **at the project root**
(CMake places it there via `RUNTIME_OUTPUT_DIRECTORY`).

### 1. With the Makefile (recommended)

```bash
make            # configure + build -> ./ft_nmap
```

Available targets:

| Target | Effect |
| --- | --- |
| `make` / `make all` | Build `ft_nmap` (default target) |
| `make tests` | Build the unit-test binary `tests_ft_nmap` |
| `make clean` | Remove the `build/` directory |
| `make fclean` | `clean` + remove the `ft_nmap` binary |
| `make re` | `fclean` + `all` |
| `make help` | Print the list of targets |

### 2. Directly with CMake

```bash
cmake -B build              # configure (only re-run when CMakeLists changes)
cmake --build build         # compile
```

### 3. Build option: sanitizers

ASan/UBSan sanitizers are **enabled by default** (useful for memory debugging).
To disable them — **mandatory on Alpine/musl**, i.e. inside the Docker
container, where they are not supported:

```bash
cmake -B build -DFT_NMAP_SANITIZERS=OFF
cmake --build build
```

This option can be passed to the Makefile via `CMAKE_GEN_FLAGS`:

```bash
make CMAKE_GEN_FLAGS=-DFT_NMAP_SANITIZERS=OFF
```

---

## Docker

The Docker environment brings up three containers on an isolated network
(`192.168.100.0/24`), which lets you scan realistic targets without touching a
real machine on your network.

| Container | IP | Role |
| --- | --- | --- |
| `ft_nmap_source` | `192.168.100.10` | Runs `ft_nmap` (privileged, `NET_RAW`/`NET_ADMIN`, project mounted at `/app`) |
| `ft_nmap_target` | `192.168.100.20` | Target to scan |
| `ft_nmap_target2` | `192.168.100.21` | Second identical target (useful for `--file` / multi-target) |

The targets run real services and dummy listeners so scans return meaningful
results:

- **SSH** on port 22 (`root:root`) and **nginx** on port 80
- **socat** listeners on well-known ports so the service name resolves: 21
  (ftp), 23 (telnet), 25 (smtp), 53 (domain), 110 (pop3), 143 (imap), 443
  (https), 445 (microsoft-ds), 3306 (mysql), 5432 (postgresql), 6379 (redis),
  8080 (http-alt), 27017 (mongod), etc.

### Container lifecycle

Build the images (once, or after changing a Dockerfile):

```bash
docker compose build
```

Start the containers:

```bash
docker compose up -d
```

Enter the **source** container (where you launch scans from):

```bash
docker exec -it ft_nmap_source bash
```

Enter a **target** (to inspect, sniff, etc.):

```bash
docker exec -it ft_nmap_target bash
docker exec -it ft_nmap_target2 bash
```

Stop and remove the containers:

```bash
docker compose down
```

### Building inside the container

A binary compiled on the host machine **will not necessarily run** inside the
container: the environment (architecture, libraries, libc) may differ. So you
have to recompile from inside the source container.

If a `build/` directory from a host build already exists, remove it first:

```bash
rm -rf build
```

Then build **with sanitizers disabled** (not supported on Alpine/musl):

```bash
cmake -B build -DFT_NMAP_SANITIZERS=OFF && cmake --build build
```

### Sniffing network traffic

#### Why go through `tcpdump` (and not Wireshark directly)

The containers run on an **isolated Docker-internal bridge network**
(`192.168.100.0/24`). The scan traffic therefore flows on an interface that
lives *inside* Docker, not on the host machine.

On macOS and Windows, Docker runs inside a Linux VM: the interface where this
traffic actually flows **is not visible** from the host's Wireshark. Selecting
an interface in Wireshark will show nothing. (On a native Linux host the
`br-xxxx` bridge does appear and Wireshark could listen on it — but that is not
portable across machines.)

The reliable, portable method is therefore to **capture with `tcpdump` from
inside the container** (which is on the `192.168.100.0/24` network via its
`eth0` interface), write a `.pcap` file into the mounted volume `/app`, and then
**open that `.pcap` in Wireshark** on the host.

#### Watching live in the terminal

Open two terminals in the source container.

**Terminal 1 — live capture:**

```bash
tcpdump -i eth0 -n -vv
```

**Terminal 2 — run a scan:**

```bash
./ft_nmap --ip 192.168.100.20 --ports 1-100
```

#### Analyzing in Wireshark

Capture into a `.pcap` file (Ctrl-C to stop) while a scan runs in another
terminal:

```bash
tcpdump -i eth0 -n -w /app/capture.pcap
```

Since `/app` is the project directory mounted as a volume, `capture.pcap`
appears directly in the `ft_nmap` folder on the host: just open it in
Wireshark.

### Test bench: reproduce every state

Each scan technique has a **finite set of possible states**, and they are **all
reproducible** on the targets. The ports below are **pre-configured
automatically** when the target container starts (listeners + `iptables` rules
set in the `CMD` of `Dockerfile.target`; netfilter rules live in the kernel and
cannot persist via a `RUN`).

Possible states per technique:

- **SYN**: `open`, `closed`, `filtered`
- **ACK**: `unfiltered`, `filtered`
- **NULL / FIN / XMAS**: `open|filtered`, `closed`, `filtered`
- **UDP**: `open`, `open|filtered`, `closed`, `filtered`

#### Bench ports and expected states

| Port | Configuration on the target | Scan to run | Expected state |
| --- | --- | --- | --- |
| `4300` | TCP listener | `SYN` | `open` |
| `4300` | TCP listener | `NULL`/`FIN`/`XMAS` | `open\|filtered` |
| `4300` | TCP listener | `ACK` | `unfiltered` |
| `4301` | free (no service, no rule) | `SYN` | `closed` |
| `4301` | free | `NULL`/`FIN`/`XMAS` | `closed` |
| `4302` | `iptables --syn -j DROP` (stateless) | `SYN` | `filtered` |
| `4302` | `iptables --syn -j DROP` | `ACK` | `unfiltered` |
| `4303` | `iptables --ctstate NEW,INVALID -j DROP` (stateful) | `SYN` | `filtered` |
| `4303` | `iptables --ctstate NEW,INVALID -j DROP` | `ACK` | `filtered` |
| `4304` | `iptables -j REJECT --reject-with icmp-host-prohibited` | `SYN`/`ACK`/`NULL`/`FIN`/`XMAS` | `filtered` |
| `4310` | UDP echo (replies to any datagram) | `UDP` | `open` |
| `4311` | free (no service, no rule) | `UDP` | `closed` |
| `4312` | `iptables -p udp -j DROP` | `UDP` | `open\|filtered` |
| `4313` | `iptables -p udp -j REJECT --reject-with icmp-host-prohibited` | `UDP` | `filtered` |

#### Running the bench

From the source container. All TCP scans over the bench's TCP ports:

```bash
./ft_nmap --ip 192.168.100.20 --ports 4300,4301,4302,4303,4304 \
          --scan SYN,ACK,NULL,FIN,XMAS --reason --verbose
```

The UDP scan over the bench's UDP ports:

```bash
./ft_nmap --ip 192.168.100.20 --ports 4310,4311,4312,4313 \
          --scan UDP --reason --verbose
```

`--verbose` forces every port to be displayed (nothing is grouped into "Not
shown"), and `--reason` shows the cause of each state.

#### The SYN vs ACK case (stateless / stateful)

Ports `4302` and `4303` illustrate the SYN/ACK complementarity (see the
[ACK scan](#tcp--ack-scan---scan-ack) section):

- `4302` (**stateless** firewall, drops only `SYN`) → `SYN(filtered)` but
  `ACK(unfiltered)`: the lone `ACK` gets through and reveals that the filter
  only targets new connections.
- `4303` (**stateful** firewall) → `SYN(filtered)` **and** `ACK(filtered)`: both
  the `SYN` (NEW) and the lone `ACK` (INVALID) are dropped.

#### UDP note: kernel ICMP rate limit

The UDP `closed` and `filtered` states rely on **ICMP errors** generated by the
target's kernel. But the kernel **rate-limits ICMP errors** (on the order of
5/second). When scanning many UDP ports at once, some `closed` ports may
therefore wrongly appear as `open|filtered` (the ICMP was throttled). The bench
only has 4 UDP ports, so it stays under the limit; to scan large UDP ranges you
need to slow down sending (throttling).

---

## Usage

```
sudo ./ft_nmap [options] (--ip <target> | --file <file>)
```

### Options

| Option | Argument | Description |
| --- | --- | --- |
| `--ip` | IP or hostname | Target to scan (repeatable) |
| `--file` | path | File containing a list of targets (one per line) |
| `--ports` | `22`, `22-32`, `22,80,443` | Ports to scan (default: `1-1024`, **max 1024 ports**) |
| `--scan` | `SYN,ACK,NULL,FIN,XMAS,UDP` | Scan type(s), comma-separated (default: all) |
| `--speedup` | `0-250` | Number of threads |
| `--packet-trace` | — | Show every packet sent and received (bonus) |
| `--reason` | — | Show the reason a port is in a given state (bonus) |
| `--verbose` | — | Show all port states (no state ignored) (bonus) |
| `--version` | — | Probe open ports to determine service/version (bonus) |
| `--os-detect` | — | Enable OS detection (bonus) |
| `--decoy` | `ip1,ip2[,ME]` | Cloak the scan with decoy source IPs, max 3; `ME` marks where the real IP goes (bonus) |
| `--help` | — | Show help |

> **Mandatory vs bonus.** Only `--help`, `--ip`, `--file`, `--ports`, `--scan`
> and `--speedup` are part of the subject's mandatory part. Every option marked
> *(bonus)* is an optional "additional flag". Note: the subject states that the
> `-v/-V` verbosity flag is not considered a valid bonus on its own.

### Running with no options

With only a target, ft_nmap uses the defaults: **ports 1-1024** and **all scan
types** (SYN, ACK, NULL, FIN, XMAS, UDP).

```bash
sudo ./ft_nmap --ip 192.168.100.20
```

### Running with options

A single scan type, a port range, showing the reason for each state:

```bash
sudo ./ft_nmap --ip 192.168.100.20 --ports 1-100 --scan SYN --reason
```

Several targets, or a list from a file:

```bash
sudo ./ft_nmap --ip 192.168.100.20 --ip 192.168.100.21 --scan SYN
sudo ./ft_nmap --file targets.txt --ports 22,80,443
```

Speed it up with several threads:

```bash
sudo ./ft_nmap --ip 192.168.100.20 --ports 1-1024 --speedup 50 --scan SYN
```

### Combining several TCP scans (and UDP)

ft_nmap can run **several techniques in the same execution**. The results of
each technique are merged into a single final state per port (see the
differences section below), and a `SCAN RESULTS` column details each
technique's result:

```bash
sudo ./ft_nmap --ip 192.168.100.20 --ports 20-25 --scan SYN,ACK,NULL --reason
```

Example output (multi-scan):

```
Starting ft_nmap at 2026-06-16 08:36 +0200
Nmap scan report for target (192.168.100.20)
Host is up.
PORT      STATE          SERVICE              SCAN RESULTS              REASON
22/tcp    open           ssh                  SYN(open) ACK(unfiltered) NULL(open|filtered)    syn-ack
23/tcp    closed         telnet               SYN(closed) ACK(unfiltered) NULL(closed)         reset

ft_nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
```

Example output (single scan):

```
Starting ft_nmap at 2026-06-16 08:36 +0200
Nmap scan report for target (192.168.100.20)
Host is up.
PORT      STATE          SERVICE
22/tcp    open           ssh
80/tcp    open           http

ft_nmap done: 1 IP address (1 host up) scanned in 0.21 seconds
```

> When a state groups more than 25 ports, they are not listed one by one: a
> single line `Not shown: N closed tcp ports (reset)` summarizes them. Use
> `--verbose` to force every port to be displayed.

---

## Differences from real nmap

ft_nmap reproduces nmap's behavior, with a few project-specific quirks:

1. **Combined final state + `unknown` state.** When several scan types are run
   together, ft_nmap merges their results into a single "definitive" state per
   port. If two techniques contradict each other, the port is marked `unknown`.
   Real nmap does not perform this merge and has no such state.

   This case is rare but possible. Concrete example: a SYN scan returns `open`
   (the port answers `SYN/ACK`) while a NULL/FIN/XMAS scan returns `closed` (the
   port answers `RST`). This happens against network stacks that answer `RST` to
   *every* probe — typically Windows — instead of the expected behavior where an
   open port ignores NULL/FIN/XMAS scans (`open|filtered`). On a "classic"
   target (Linux, etc.) the techniques agree and `unknown` does not appear.

2. **`SCAN RESULTS` column.** In multi-scan mode, ft_nmap adds a column showing
   the result of *each* technique for each port (e.g. `SYN(open)
   ACK(unfiltered)`), in addition to the combined state in the `STATE` column.

3. **Project-specific limits:**
   - at most **1024 ports** per run;
   - at most **250 threads** (`--speedup`);
   - at most **3 decoys** (`--decoy`, bonus);
   - default port range **1-1024**;
   - **IPv4 only**.

4. **`--os-detect` (bonus): simplified heuristic.** OS detection relies on the
   observed TTL and TCP window size, not on nmap's fingerprint database. It
   requires at least one open TCP port (so a SYN scan).

5. **`--version` (bonus): simplified banner-grab.** Version detection queries
   open TCP ports and matches the received banner against regular expressions
   (pcre2), instead of nmap's full probe database.

---

## Port states and what the responses mean

### Possible states

| State | Meaning |
| --- | --- |
| `open` | The port is not filtered and a service is listening on it. |
| `closed` | The port is reachable but no application is listening on it. |
| `filtered` | A firewall blocks communication: impossible to tell whether the port is `open` or `closed`. |
| `unfiltered` | The port is reachable (it answers), but we cannot tell whether it is `open` or `closed` (ACK scan response). |
| `open\|filtered` | The port is either open or filtered; the scan cannot decide (NULL/FIN/XMAS and UDP). |
| `unknown` | ft_nmap-specific: several techniques gave contradictory results for this port. |

> A `filtered` port does not necessarily prevent knowing which service is meant
> to run on it: the displayed name comes from the port number (`nmap-services`
> table).

### Responses obtained per scan technique

#### TCP — SYN scan (`--scan SYN`)

Half-open scan: we send a `SYN` and wait for the reply without completing the
connection (we send a `RST` if the server answers `SYN/ACK`).

| Response received | Assigned state |
| --- | --- |
| `SYN/ACK` | `open` |
| `RST` | `closed` |
| No response (even after retransmission) | `filtered` |
| ICMP unreachable error (type 3, code 1, 2, 3, 9, 10 or 13) | `filtered` |

> **Why SYN?** It is the reference scan: the most accurate for finding what is
> *open*, because it cleanly distinguishes `open` / `closed` / `filtered`. Since
> we never complete the connection (we cut it with a `RST` after the `SYN/ACK`),
> it is fast and leaves fewer traces than a full connection. It is the logical
> starting point for any scan; the other techniques exist to fill in what it
> cannot see (firewall, UDP, evasion).

#### TCP — ACK scan (`--scan ACK`)

Sends a packet with only the `ACK` flag set. Used to determine whether a port is
filtered (and thus to map firewall rules).

| Response received | Assigned state |
| --- | --- |
| `RST` | `unfiltered` |
| No response (even after retransmission) | `filtered` |
| ICMP unreachable error (type 3, code 1, 2, 3, 9, 10 or 13) | `filtered` |

> **Why ACK on top of SYN?** SYN tells you what is *open*; ACK never does (an
> `open` port and a `closed` port both answer `RST` → `unfiltered`). ACK is used
> to probe the **firewall**: a port that is `filtered` under SYN but comes back
> `unfiltered` under ACK reveals a *stateless* firewall that only blocks new
> connections (`SYN`); if it stays `filtered`, the firewall is *stateful* and
> blocks lone ACKs too. The two scans are complementary: SYN = which ports are
> open, ACK = how the firewall is configured.

#### TCP — NULL / FIN / XMAS (`--scan NULL,FIN,XMAS`)

- **NULL**: no flag set (`-sN` in nmap).
- **FIN**: only the `FIN` flag set (`-sF` in nmap).
- **XMAS**: `FIN`, `PSH` and `URG` flags set (`-sX` in nmap).

| Response received | Assigned state |
| --- | --- |
| No response (even after retransmission) | `open\|filtered` |
| `RST` | `closed` |
| ICMP unreachable error (type 3, code 1, 2, 3, 9, 10 or 13) | `filtered` |

> **Why NULL / FIN / XMAS?** These scans exploit RFC 793: a *closed* port must
> answer `RST` to any packet lacking `SYN`/`RST`/`ACK`, whereas an *open* port
> must ignore it (no response). Hence no response = `open|filtered` and `RST` =
> `closed`. Two benefits over SYN: **stealth** (no `SYN`, so they often evade
> IDSs and logs that watch for connection starts) and **evasion** of *stateless*
> firewalls that only filter `SYN`. Big limitation: it only works against
> network stacks that follow the RFC (many Unixes); Windows, some Cisco gear,
> etc. answer `RST` to everything → every port appears `closed`. The three
> variants (no flag / `FIN` / `FIN`+`PSH`+`URG`) are logically equivalent; they
> differ only by the flags, which helps bypass a filter that would catch one
> combination but not another.

#### UDP scan (`--scan UDP`)

Sends an (empty) UDP datagram to the target port.

| Response received | Assigned state |
| --- | --- |
| Any UDP response from the target port | `open` |
| No response (even after retransmission) | `open\|filtered` |
| ICMP port unreachable error (type 3, code 3) | `closed` |
| Other ICMP unreachable error (type 3, code 1, 2, 9, 10 or 13) | `filtered` |

> **Why UDP?** The previous scans only see TCP, yet many critical services run
> over **UDP**: DNS (53), SNMP (161), DHCP (67/68), NTP (123)... Without a UDP
> scan, these services are completely invisible. The trade-off: UDP has no
> handshake, so detection is slower and less reliable. An open port usually
> answers nothing (hence `open|filtered`), and only an ICMP *port unreachable*
> lets you assert that a port is `closed`. This is the scan to use whenever you
> want a complete picture of the target, not just its TCP surface.

---

## Architecture: libpcap and netfilter in the kernel

To understand *how* ft_nmap sends its probes and collects the replies — and why
a firewall produces the states seen above — you need to look at a packet's path
**inside the kernel**.

![Path of an incoming packet inside the kernel: capture (BPF/libpcap) on one side, IP routing + netfilter on the other, plus the datalink types on the capture side](docs/kernel-packet-flow.png)

*(High-resolution PDF version: [`docs/kernel-packet-flow.pdf`](docs/kernel-packet-flow.pdf).)*

### The incoming packet is duplicated

When a TCP packet arrives on the interface (`eth0`), the kernel sends it down
**two independent branches**:

1. **Packet capture (libpcap).** A **BPF** program filters packets, fills a
   buffer, and user space reads it through a *pcap handle*. This is what
   `tcpdump` **and ft_nmap** do to read the probe replies.
2. **IP Routing + Netfilter.** The packet's "normal" path: the kernel routes it
   (`Local` if it is addressed to us) then submits it to the netfilter rules,
   which decide `continue` (→ `send to socket`: raw, TCP, UDP, ICMP) or
   `drop`/`STOP`.

### The key point: capture happens *before* netfilter

For **inbound** traffic, the BPF tap happens **before** netfilter rules. Direct
consequence: **libpcap sees even the packets that netfilter is about to drop.**
This is why `tcpdump` can display a packet that an `iptables -j DROP` rule
discards right afterward — the two mechanisms live in the kernel but at
different stages.

### Where ft_nmap sits

ft_nmap uses both ends of the diagram, on the *user/dev space* side:

- **`socket raw`** to **craft and send** its probes (SYN, ACK, UDP
  datagrams...) with its own headers.
- **`pcap handle`** to **capture the replies** (`SYN/ACK`, `RST`, ICMP errors)
  via the packet-capture branch, independently of regular sockets.

### Datalink types (the `datalink_type` panel)

When libpcap hands you a packet, it does **not always start at the same place**:
depending on the captured interface, the frame is preceded by a different
link-layer header. libpcap reports which one via `pcap_datalink()`, and ft_nmap
uses it to compute **where the IP header begins** before parsing the reply. The
cases ft_nmap handles:

| Datalink type | Header before the IP | Typical case |
| --- | --- | --- |
| `DLT_EN10MB` | **Ethernet** header (14 bytes) | regular Ethernet interface (`eth0`); Linux loopback |
| `DLT_NULL` | **BSD loopback** header (4 bytes: address family) | loopback on BSD/macOS, e.g. `127.0.0.1` on macOS |
| `DLT_RAW` | **none**: the frame starts directly at the IP header | point-to-point interfaces / tunnels |

Concretely, ft_nmap looks at the datalink type, **strips the corresponding
link-layer header** (nothing for `DLT_RAW`), then reads the IP header followed
by the TCP/UDP/ICMP header. This is what lets it parse replies regardless of the
interface, without assuming there is always an Ethernet header.

> The diagram also shows **`DLT_LINUX_SLL`** (the "cooked" `sll_header`).
> ft_nmap **deliberately** does not handle it: this type only appears when
> capturing on the special `any` interface, which the project never selects by
> default — it always picks the real interface leading to the target.

### netfilter / iptables, concretely

Linux's firewall is the **netfilter** framework built into the kernel.
`iptables` is merely the user-space tool that installs rules into it; the kernel
is what applies them. Rules are organized into **chains** according to the
packet's path: `INPUT` (destined for the machine), `OUTPUT` (emitted by it),
`FORWARD` (in transit). Each rule is a **condition** (protocol, port, TCP flags,
connection state...) followed by a **target** (`ACCEPT`, `DROP`, `REJECT`...);
the kernel walks the chain and the **first matching rule** decides.

The link with port states: a `DROP` target discards the packet **without
replying**. On the scanner side, "no response" → `filtered`. And the kernel's
**conntrack** module, which tracks the state of every connection (`NEW`,
`ESTABLISHED`, `INVALID`...), is what enables a **stateful** firewall: it is the
one that recognizes that a lone `ACK` matches no established connection
(`INVALID`) and drops it — see the
[test bench](#test-bench-reproduce-every-state).

---

## Tests

Build and run the unit tests (greatest + pcre2):

```bash
make tests
ctest --test-dir build --output-on-failure
```

The scan suite sends raw packets: it **requires root** at runtime.
