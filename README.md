# Network Analyser

A field-engineering toolkit that combines IT networking, industrial Ethernet, serial
communication and IoT protocols in one GPUI app. Tools are grouped in segments in the
sidebar:

| Segment | Tools |
|---|---|
| **Network Discovery** | LAN Scan · Gateway Discovery · Traceroute · DNS Lookup · Reverse DNS · DHCP Analyser · Wake-on-LAN |
| **Ports & Services** | Port Scan · Service Versions · TLS Certificates · SNMP · NTP Analyser · SFTP / SSH Tester · DHCP Client Tester · DNS Client Tester |
| **Packet Analysis** | Live Packet Capture · PCAP / PCAPNG Viewer · Protocol Decoder · TCP Streams · HTTP Reconstruction · TCP Handshakes · DNS Monitor · Packet Statistics |
| **Industrial Protocols** | Modbus RTU / TCP · CAN Bus Analyser · PROFINET · BACnet · OPC UA |
| **IoT Protocols** | MQTT · WebSocket |
| **Serial Communication** | Serial Monitor |
| **Security & Audit** | Open Port Audit · Firewall Tester · Rogue DHCP Tester · ARP Spoof Detector · DNS Security · Anomaly Detector |
| **Performance** | Bandwidth Monitor · Throughput Tester · Latency Monitor · Jitter Tester · Packet Loss Tester · Wi-Fi Analyser · Uptime Monitor |
| **Network Utilities** | Network Configuration · Public IP · IP Geolocation · Base64 |

Coming next: more industrial and IoT protocols (CAN bus, PROFINET, BACnet, OPC UA, MQTT, SNMP,
NTP, WebSocket, SFTP, DHCP / DNS client testers).

Click a tool in the sidebar, or use **Alt+↑ / Alt+↓** to move between tools. Click a group
header to collapse or expand it (or use *Expand all* / *Collapse all*); the box at the top
filters tools by name or purpose, and Enter opens the first match. Open groups are remembered. **Ctrl+B**
(**⌘B**) hides the sidebar. `--tool NAME` opens a tool directly (see [Run](#run)).

## LAN Scan

What it collects per host:

| Info | Source |
|---|---|
| Alive / ping RTT / TTL | ICMP via system `ping`, TCP connect/RST, kernel ARP table |
| Hostname | Reverse DNS, unicast mDNS (`.local`), NetBIOS (UDP 137), UPnP friendly name |
| MAC + vendor | `/proc/net/arp` (or NetBIOS) + IEEE OUI registry |
| Open ports | TCP connect scan of ~60 common ports (`netinfo::DEFAULT_PORTS`) |
| Banners | First line of each service (SSH version, FTP, SMTP…), HTTP status / `Server` / `<title>` |
| UPnP / SSDP | Server string, friendly name, manufacturer, model, device type |
| NetBIOS | Machine name, workgroup, logged-in user |
| OS & device type | Heuristics from TTL, ports, banners, vendor, mDNS, UPnP |

**Proxy interception detection:** before each scan the app connects to the reserved
TEST-NET addresses (RFC 5737). If ports "open" there, a transparent proxy or security
agent is answering for every address. Those ports are excluded and a warning appears in
the status bar.

## Port Scan

Targets can be mixed and comma/space separated: `example.com, 10.0.0.5, 10.0.0.0/28, 2001:db8::1`.
A domain name is resolved and its first IPv4 and first IPv6 address are scanned.
Ports: `top` (≈120 common services), ranges and lists (`1-1024,3389,8000-8100`), or the
presets *Top ports*, *1-1024*, *Industrial* (Modbus 502, S7 102, OPC UA 4840, IEC-104 2404,
DNP3 20000, EtherNet/IP 44818, BACnet 47808, MQTT…) and *All 65535*. Open ports get a banner
(SSH/FTP/SMTP greeting, HTTP status, `Server` and `<title>`); port 502 is asked for its Modbus
device identification. Results export to `~/port-scan-<timestamp>.csv`.

Only scan hosts you own or are authorised to test.

## Packet Capture

The **Packet Analysis** tools share one session: start a capture or open a file in any of
them and look at the same packets in all the others. Links such as *Follow TCP stream*,
*Handshake* and *Show packet* jump between them.

### Live Packet Capture

- Pick an interface (the one with the default route is preselected), optionally a BPF
  capture filter (`tcp port 502`, `host 10.0.0.5`, `not arp`), and press **Start capture**.
- **Stop after** ends the capture by itself: packets, time and/or size (`1000`, `60s`, `5min`,
  `50MB`). *Headers only* keeps 128 bytes per packet, *Promiscuous* captures frames for other
  hosts too, and *Save to .pcap* writes everything to `~/capture-<timestamp>.pcap`.
- The display filter matches protocols (also enclosing ones: `gre`, `vlan`), addresses, ports and
  the info column; every term must match and `!term` excludes (`modbus 10.0.0.20`, `!arp !mdns`).
  **Save shown** writes the filtered packets.
- Click a packet for its decoded layers and hex dump. The list keeps 200,000 packets;
  statistics and handshakes keep counting beyond that.

### PCAP / PCAPNG Viewer

Opens `.pcap` (either byte order, µs or ns), `.pcapng` and gzip-compressed files with a native
reader: no capture rights or Npcap needed (only a BPF filter needs them). pcapng files with several
interfaces and link types work, packet comments are shown, and *File details* lists the format,
host, capture application, interfaces (snap length, filter, drops), names and block types. Damaged
or cut-off files are read up to the damage. Recent files are listed; `--open FILE` opens one on start.

### Protocol Decoder

Identifies protocols by **content signature** first, so services on unusual ports are
recognised, and by port otherwise; each packet says which. The protocol tree filters the list.
*Paste hex* decodes a frame from Wireshark, `tcpdump -x`, `xxd` or `hexdump -C` output.

Decoded: Ethernet, VLAN, MPLS, PPPoE, STP, LLDP, Linux cooked, loopback, raw IP, ARP, IPv4/IPv6,
GRE, IP-in-IP, VXLAN, ICMP (with the packet that caused the error) and ICMPv6, IGMP, TCP with
options, UDP, DNS/mDNS/LLMNR, DHCP, DHCPv6, NTP, SSDP, NBNS, HTTP, TLS (SNI, ALPN, versions, cipher,
TLS 1.2 certificate, alerts), DTLS, QUIC, SSH, SMB, RDP, MQTT, SNMP, CoAP, SIP, RTSP, STUN,
WireGuard, RADIUS, TFTP, BGP, AMQP, Redis, MySQL, PostgreSQL, VNC and, for industrial networks,
Modbus, S7comm, OPC UA, EtherNet/IP, DNP3, IEC 104 and BACnet.

### TCP Streams

Reassembles both directions of every connection: segments are put in order, retransmissions and
overlaps removed, and data missing from the capture is marked instead of being skipped silently.
Follow the conversation as text or hex, one or both directions, and save the raw bytes.

### HTTP Reconstruction

Pairs HTTP/1.x requests with their responses on any port, joins chunked bodies and decodes gzip and
deflate (Brotli and zstd are shown raw). Shows headers, bodies, waiting and total time; bodies
can be saved and requests copied as `curl`. HTTPS, HTTP/2 and HTTP/3 content is not reconstructed.

### TCP Handshakes

Result of every connection attempt (complete, refused, no answer, half-open…), round trip to the server
and to the client, SYN retransmissions, MSS / window scale / SACK of both sides, how the connection ended,
and findings such as missing window scaling, zero windows, retransmission rate and possible SYN floods.

### DNS Monitor

Matches queries with their answers: response time, result, repeated and unanswered queries, and totals per
name, DNS server and client. Flags two different answers to one query (spoofing), failing servers,
NXDOMAIN bursts and names that look like DNS tunnelling. DNS over TLS / HTTPS is encrypted and not visible.

### Packet Statistics

Totals, average and peak rates, traffic over time, protocol distribution and hierarchy, packet sizes,
unicast / multicast / broadcast, TCP flags, top talkers, service ports and conversations.

### Permissions

Capturing needs raw-socket rights. The same rights are used by the tools that send raw Ethernet frames: PROFINET, DHCP Client Tester, DHCP Analyser and Rogue DHCP Tester. CAN through slcan adapters needs serial-port access (`dialout` group on Linux):

| OS | Setup |
|---|---|
| Linux | `sudo setcap cap_net_raw,cap_net_admin=eip $(command -v network_analyser)` once (or run as root) |
| macOS | Access to `/dev/bpf*`, e.g. Wireshark's *ChmodBPF* helper, or run with `sudo` |
| Windows | Install [Npcap](https://npcap.com/#download) (the installer offers the link). Without Npcap everything except capture still works |

## Serial

Ports are listed with their USB VID:PID, manufacturer and serial number. Choose baud, data
bits, parity, stop bits and RTS/CTS, then **Connect**. Received bytes are grouped into frames
by silence on the line (*Frame gap*, automatically 3.5 character times in Modbus view) and
shown as **Text**, **Hex** or decoded **Modbus RTU** with CRC check, plus RX/TX byte counts,
frame and CRC-error statistics. Send text (with `\r \n \xNN` escapes and a line ending) or
hex (optionally with the Modbus CRC appended). **Detect baud** listens at each standard rate
and scores readable text and valid Modbus frames (the device must be transmitting).
**Save log** writes a hex/ASCII/decoded log to `~/serial-log-<timestamp>.txt`.

On Linux, add yourself to the `dialout` group to open serial ports:
`sudo usermod -aG dialout $USER`, then log in again.

## Modbus

- **Modbus TCP** (host, port 502) or **Modbus RTU** (serial port and line settings; 8E1 is the
  Modbus default), unit ID and timeout.
- **Read** coils (FC1), discrete inputs (FC2), holding registers (FC3) or input registers (FC4)
  once, or **Poll** at an interval. Values show their 0-based address and 1-based reference
  (`40001`…), formatted as UInt16, Int16, hex, binary, Float32 or UInt32 (with word swap).
  Click a row to use its address for writing.
- **Write** a single coil/register (FC5/FC6) or several (FC15/FC16): `123`, `-5`, `0x1F`,
  `1,2,3`; coils take `1/0` or `on/off`.
- **Discover**: scan unit IDs on the current link (an RTU bus or a TCP gateway), read device
  identification (FC43/14), or find Modbus TCP servers in an IP range.
- **Traffic** shows every frame in hex with its decoding, and the status bar counts requests,
  exceptions, errors and the average response time.

## Gateway Discovery

Runs automatically when opened: default routes (IPv4 and IPv6, with metrics), the gateway's
reachability, MAC and vendor, open management ports (SSH, Telnet, HTTP/S, DNS, UPnP) and web
UI title, the external address the router reports via **NAT-PMP** and **UPnP-IGD**, a
**double-NAT / carrier-grade NAT** check, and a health check of every configured DNS server
(including the real upstreams behind a local stub such as systemd-resolved's 127.0.0.53).

## Traceroute

Path to a host with per-hop address, name, loss, last / average / best / worst latency and a
latency bar. It needs no administrator rights: the system `ping` is run with an increasing TTL
(all hops in parallel) to discover the path, then every hop is timed with direct echoes. Hops
that ignore direct pings show an estimate marked "≈". IPv4 and IPv6.

## DNS Lookup and Reverse DNS

- **DNS Lookup** queries any record type (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR, CAA,
  HTTPS, DS, DNSKEY, TLSA, ANY…) on the system resolver, Google, Cloudflare, Quad9, OpenDNS or
  any server (`10.0.0.53`, `[::1]:5353`), over UDP or TCP, with the DNSSEC (DO) and recursion
  flags. It shows the answer, authority and additional sections with TTLs, the response
  code, flags and timing. **Compare resolvers** sends the same query to every system and public
  resolver side by side. Typing an IP address looks up its PTR name.
- **Reverse DNS** resolves PTR names for lists and ranges (`192.168.1.0/24`, IPv6 addresses)
  in parallel and checks that each name resolves back to the same address (forward-confirmed
  reverse DNS).

## DHCP Analyser

Listens for DHCP on the chosen interface and lists every message (DISCOVER, OFFER, REQUEST, ACK,
NAK…) with the client's MAC and vendor, hostname, offered or requested address, server and
vendor class; click a message for every decoded option (router, DNS, lease and renewal times,
domain search, classless routes, relay agent information, PXE architecture…). A summary lists
each DHCP server seen, with a warning when more than one answers.

**Find DHCP servers** broadcasts a DHCPDISCOVER (from this interface's MAC or a random one)
and highlights every offer it receives. No REQUEST is sent, so no address is leased. This
needs packet-capture rights (see [Packet Capture](#packet-capture)).

## Wake-on-LAN

Sends a magic packet (UDP 9 or 7, optional SecureOn password) to a subnet broadcast, the
global broadcast or a unicast address, then optionally pings the device until it answers.
Devices can be saved, and any device from the last LAN Scan can be picked by click.

## Service Versions and TLS Certificates

- **Service Versions** finds open ports and then speaks each protocol to identify the product
  and version: SSH, FTP, SMTP, POP3, IMAP, HTTP(S) (`Server`, `X-Powered-By`, page title),
  MySQL / MariaDB, PostgreSQL (and whether it offers TLS), Redis, memcached, VNC, RDP (security
  layer), MQTT (anonymous access), DNS (`version.bind`), Docker API, Elasticsearch and Modbus
  device identification. Security notes flag unauthenticated services and version disclosure.
- **TLS Certificates** grades each host A–F and shows the negotiated protocol and cipher, every
  certificate in the chain (subject, issuer, validity and days left, names, key type and size,
  signature, SHA-256 fingerprint), whether the chain is trusted by the system's CA store and
  matches the name, and which of TLS 1.3 / 1.2 / 1.1 / 1.0 the server accepts. Legacy-only
  servers are still analysed. Ports 25, 587, 143, 110 and 21 use STARTTLS automatically.

## SNMP, NTP, SSH and client testers

- **SNMP**: v1 / v2c device summary (system group and the interface table with live traffic
  rates), Get / GetNext / GetBulk / Walk / Set by OID or name, a check for default or writable
  community strings, SNMPv3 engine discovery and a subnet sweep for agents.
- **NTP Analyser**: samples each server several times (every address of a pool) and keeps the
  best sample: offset, delay, jitter, stratum, decoded reference ID, leap and root distance.
  Finds the system's configured time servers, flags servers that disagree and judges the local
  clock.
- **SFTP / SSH Tester**: without credentials it reads the banner, the server's algorithms (weak
  ones and Terrapin exposure flagged), the host-key fingerprint (remembered and checked on later
  connections) and the login methods offered. After logging in with a password or key it
  browses files over SFTP, downloads, uploads and runs a write test, with timings.
- **DHCP Client Tester**: a full DISCOVER → OFFER → REQUEST → ACK exchange from a test MAC (the
  OS's DHCP client is untouched), timing each step and listing every offer. It ARP-checks the
  leased address (DECLINE on conflict), can test INFORM, releases the lease afterwards and can
  repeat for a timing series. Needs packet-capture rights.
- **DNS Client Tester**: benchmarks resolvers over UDP, TCP and DNS-over-TLS with cached and
  uncached names and ranks them; checks NXDOMAIN hijacking, DNSSEC validation, EDNS, TCP and
  truncation handling, answer rewriting, consistency between resolvers and rebinding protection.

## Industrial and IoT protocols

- **CAN Bus Analyser**: CAN and CAN FD through SocketCAN (Linux) or an slcan / Lawicel USB adapter
  (any OS). Frame log, per-ID rate, period and jitter with changed bytes highlighted, bus load
  estimate and error frames; send single or periodic frames in `cansend` syntax.
- **PROFINET**: DCP Identify All finds every device on the segment (station name, type, vendor /
  device ID, role, IP settings); flash a device's LED and set its name or IP (temporary or
  permanent, with confirmation). Listen mode shows cyclic real-time frames (cycle time,
  RUN / STOP, data valid), alarms and LLDP neighbours. Needs packet-capture rights.
- **BACnet**: BACnet/IP Who-Is discovery (also through BACnet routers and BBMDs), device
  properties, the full object list with names, present values, units and status flags, and a
  manual ReadProperty form.
- **OPC UA**: a server's endpoints, security policies and login types, with insecure setups
  flagged (no security, anonymous access, clear-text passwords, deprecated policies, certificate
  problems). Connects on any endpoint: unsecured, Sign or SignAndEncrypt (Basic256Sha256,
  Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss; Basic256 and Basic128Rsa15 marked deprecated), as
  anonymous, with a user name and encrypted password, or with an X.509 user certificate. It
  creates its own client certificate on first use (or uses yours); the server's administrator
  must trust it after the first attempt. You trust the server's certificate once and are warned
  if it changes. Then browse the address space, read node attributes and watch live values.
- **MQTT**: an MQTT 3.1.1 / 5.0 client over TCP or TLS. Subscribe with wildcards and watch a live
  topic tree with counts, rates and payloads (text, JSON or hex); publish at QoS 0 / 1 / 2 with
  retain; broker statistics from `$SYS`; a connection log with reason codes explained.
  Authentication is either **username / password** or **certificates (mutual TLS)**: a CA
  certificate (optional; the system store otherwise), a client certificate and its private key
  (PEM or DER; PKCS#8, RSA or EC keys). TLS failures such as an untrusted client certificate,
  a missing one, or a broker using an old X.509 v1 certificate are explained in the log.
- **WebSocket**: `ws://` and `wss://` with custom headers, subprotocols and Origin; shows the
  upgrade request and response; send text, binary or pings and follow a frame log with ping
  round-trip times and explained close codes.

## Security & Audit

- **Open Port Audit** scans hosts or ranges for ~120 ports and rates every open port against
  built-in rules (Telnet, SMB, RDP, databases, Docker API, Redis, Modbus, S7, DNP3, EtherNet/IP,
  BACnet…) with severity, risk and recommendation. **Save as baseline** remembers the result;
  later audits highlight ports that appeared or closed.
- **Firewall Tester**: *Outbound policy* checks which TCP ports this network lets out (against
  a host that accepts every port, `portquiz.net` by default and configurable), plus external
  DNS, NTP and ping. *Target path* classifies ports on a host as open, closed (reset) or
  filtered (dropped) and explains what that says about the firewall in front of it.
- **Rogue DHCP Tester** sends DHCPDISCOVERs (no lease is taken) and flags every server that is
  not on your saved list of authorised DHCP servers.
- **ARP Spoof Detector** watches the OS ARP table (no special rights) and, optionally, ARP
  traffic: a gateway whose MAC changes, one MAC answering for the gateway and other addresses,
  gratuitous-ARP floods, ARP scans and IP conflicts.
- **DNS Security** checks a domain: name-server redundancy and SOA consistency, zone transfer
  (AXFR) on every name server, DNSSEC (DS, DNSKEY, validation), SPF (policy, 10-lookup limit),
  DMARC, DKIM (common and your own selectors), MTA-STS, TLS-RPT, CAA, plus whether your
  resolver validates DNSSEC and whether a given server is an open resolver.
- **Anomaly Detector** analyses live traffic in 10-second windows: port scans and host sweeps,
  SYN / ICMP floods, broadcast and ARP storms, DHCP starvation, DNS tunnelling and NXDOMAIN
  bursts, duplicate IPs, clear-text logins (Telnet, FTP, POP3/IMAP, HTTP Basic), new devices
  (after a one-minute learning period) and traffic spikes.

Rogue DHCP, ARP traffic watching and the Anomaly Detector need packet-capture rights.

## Performance

- **Bandwidth Monitor**: live download / upload rate, peaks, totals, packets per second and
  errors for every interface, with two-minute charts.
- **Throughput Tester**: start the server on one machine and run the client on another for
  upload or download tests with 1–16 parallel TCP streams and a per-second chart (TCP/UDP
  port 5299 by default; open it in the firewall). The **HTTP download test** measures internet
  throughput against any large file URL (Cloudflare's speed-test endpoint by default).
- **Latency Monitor**, **Jitter Tester**, **Packet Loss Tester** and **Uptime Monitor** probe
  targets by ICMP ping, TCP connect, HTTP(S), DNS query or UDP echo (the Throughput Tester
  server answers UDP echo, which allows sub-100 ms intervals).
  - Latency: last / average / min / max / p95 / loss per target with a strip chart.
  - Jitter: RFC 3550 jitter, standard deviation, RTT distribution and a VoIP MOS estimate
    (ITU-T E-model).
  - Packet loss: loss rate, number of loss bursts and the longest burst, with a timeline.
  - Uptime: up / down state (two failed checks = outage), availability and an outage log.
- **Wi-Fi Analyser**: nearby networks with signal, band, channel, security (weak ones flagged)
  and vendor, your current link, per-channel congestion for 2.4 and 5 GHz and the
  least-congested channel. Uses NetworkManager on Linux, `system_profiler` on macOS and
  `netsh` on Windows (which needs Location access).

## Network Utilities

- **Network Configuration**: hostname, interfaces (type, state, MAC and vendor, MTU, link speed,
  IPv4 / IPv6 addresses), the routing table, DNS servers and the neighbour (ARP) cache.
- **Public IP**: your public IPv4 and IPv6 addresses and whether this machine is behind NAT.
- **IP Geolocation**: location, network owner (ASN / ISP) and time zone of any address, with a
  map link.
- **Base64**: encode / decode, standard or URL-safe alphabet, padding, 76-column MIME wrapping;
  binary results are shown as a hex dump.

**Online lookups** (Public IP, IP Geolocation) only contact a provider when you press the
button, and the tool shows which host it will contact. The provider URLs are configurable
(saved in `settings.json`, see below), so you can use your own service or a paid one:

| Tool | Default | Format |
|---|---|---|
| Public IPv4 / IPv6 | `https://api.ipify.org?format=json` / `https://api6.ipify.org?format=json` | plain text or JSON with an `ip` field |
| Geolocation | `https://ipapi.co/{ip}/json/` | any JSON; `{ip}` is replaced, e.g. `https://ipinfo.io/{ip}/json?token=…` |

Settings (provider URLs, the firewall test host, the HTTP download test URL, authorised DHCP
servers, saved Wake-on-LAN devices) live in `settings.json`, and audit baselines in
`audit-baseline.json`, in
`~/.local/share/network_analyser/` (Linux), `~/Library/Application Support/network_analyser/`
(macOS) or `%APPDATA%\network_analyser\` (Windows).

## Install

Download the file for your system from the [Releases](../../releases) page. Every release also
has a `SHA256SUMS.txt`. To check a download, run `sha256sum -c SHA256SUMS.txt --ignore-missing`
on Linux, `shasum -a 256 <file>` on macOS, or `Get-FileHash <file>` in Windows PowerShell.

| System | File |
|---|---|
| Debian, Ubuntu, Mint, Pop!_OS | `network-analyser_<version>_amd64.deb` |
| Fedora, RHEL, Rocky/Alma, openSUSE | `network-analyser-<version>-1.x86_64.rpm` |
| Any other Linux (Arch, Manjaro, Void…; glibc 2.35+) | `network-analyser-<version>-linux-x86_64.tar.gz` |
| macOS 11+ (Apple Silicon and Intel) | `network-analyser-<version>-macos-universal.dmg` |
| Windows 10/11 x64 (installer) | `network-analyser-<version>-windows-x86_64-setup.exe` |
| Windows 10/11 x64 (portable) | `network-analyser-<version>-windows-x86_64.zip` |

The LAN Scan, Port Scan and Modbus TCP tabs work right after installing. **Live Packet Capture** and
**Serial / Modbus RTU** need the one-time permission steps listed for your system below.

### Linux: Debian / Ubuntu / Mint / Pop!_OS

1. Install the package. apt pulls in libpcap, ping and the graphics libraries automatically:
   ```sh
   sudo apt install ./network-analyser_*_amd64.deb
   ```
2. Allow packet capture without root (needed only for the Packet Capture tab):
   ```sh
   sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/network_analyser
   ```
3. Allow serial-port access (Serial and Modbus RTU tabs), then **log out and back in**:
   ```sh
   sudo usermod -aG dialout $USER
   ```
4. Start **Network Analyser** from the applications menu (normal, kiosk and windowed entries),
   or run `network_analyser` in a terminal.

To uninstall, run `sudo apt remove network-analyser`.

### Linux: Fedora / RHEL / Rocky / Alma / openSUSE

1. Install the package:
   ```sh
   sudo dnf install ./network-analyser-*.x86_64.rpm      # Fedora, RHEL, Rocky, Alma
   sudo zypper install ./network-analyser-*.x86_64.rpm   # openSUSE
   ```
2. Allow packet capture: `sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/network_analyser`
3. Allow serial-port access, then log out and back in: `sudo usermod -aG dialout $USER`
4. Start it from the applications menu or with `network_analyser`.

To uninstall, run `sudo dnf remove network-analyser` (or `sudo zypper remove network-analyser`).

### Linux: any other distribution (tarball)

1. Install the runtime libraries if they are missing: libpcap, a Vulkan driver (Mesa),
   libxkbcommon, Wayland/X11 client libraries and `ping`. For example:
   ```sh
   sudo pacman -S --needed libpcap vulkan-icd-loader mesa libxkbcommon-x11 wayland iputils   # Arch / Manjaro
   ```
2. Extract the archive and run the installer:
   ```sh
   tar xzf network-analyser-*-linux-x86_64.tar.gz
   cd network-analyser-*-linux-x86_64
   ./install.sh          # for your user only, into ~/.local
   sudo ./install.sh     # or system-wide, into /usr/local
   ```
3. Allow packet capture. The path is the one `install.sh` printed:
   ```sh
   sudo setcap cap_net_raw,cap_net_admin=eip ~/.local/bin/network_analyser
   ```
4. Allow serial-port access, then log out and back in. The group is `uucp` on Arch-based
   systems and `dialout` elsewhere:
   ```sh
   sudo usermod -aG uucp $USER      # Arch / Manjaro
   sudo usermod -aG dialout $USER   # most others
   ```

To uninstall, run `./install.sh --uninstall` (with `sudo` for a system-wide install).

**Linux notes**
- One binary supports both **Wayland** and **X11**. It uses Wayland when `WAYLAND_DISPLAY` is
  set and X11 otherwise. `--x11` forces X11 (XWayland under a Wayland session) and
  `--wayland` forces native Wayland.
- A Vulkan driver is required. Mesa (`mesa-vulkan-drivers` on Debian/Ubuntu/Fedora) covers
  Intel, AMD and software rendering. On NVIDIA, use the proprietary driver.
- Rebuilding or replacing the binary drops the `setcap` rights; run the command again.

### macOS 11+ (Apple Silicon and Intel)

1. Open the `.dmg` and drag **Network Analyser** into **Applications**.
2. The app is ad-hoc signed but not notarized, so on first launch right-click it → **Open** →
   **Open**. Alternatively, remove the quarantine flag once:
   ```sh
   xattr -dr com.apple.quarantine "/Applications/Network Analyser.app"
   ```
3. When asked, allow **Local Network** access. You can change this later in System Settings →
   Privacy & Security → Local Network. Without it, scans find nothing.
4. **Packet capture** needs read access to `/dev/bpf*`. The easiest way is to install
   [Wireshark](https://www.wireshark.org/download.html) and run its **Install ChmodBPF**
   package, which grants access to the `access_bpf` group at every boot. A temporary
   alternative until the next reboot is `sudo chmod o+r /dev/bpf*`. libpcap itself ships with macOS.
5. **Serial ports** need no extra permission. USB adapters appear as
   `/dev/cu.usbserial-*` or `/dev/cu.usbmodem*`. Adapters with CH340/CH341 or older
   Prolific chips may need the vendor's macOS driver; FTDI and CP210x work out of the box on
   recent macOS.
6. To run with command-line options:
   ```sh
   "/Applications/Network Analyser.app/Contents/MacOS/network_analyser" --windowed
   ```

To uninstall, move the app from Applications to the Trash.

### Windows 10 / 11 (x64)

**Installer (recommended)**

1. Run `network-analyser-<version>-windows-x86_64-setup.exe`. It is unsigned, so SmartScreen
   may warn: click **More info → Run anyway**.
2. Choose *Install for all users* (needs admin) or *Install for me only*.
3. On the last page, tick **Download Npcap** if you want the Packet Capture tab; the option
   only appears when Npcap is missing.
4. Start it from the Start menu: **Network Analyser**, **(Kiosk, scan on start)** or
   **(Windowed)**.

To uninstall, use Settings → Apps → Installed apps → Network Analyser → Uninstall.

**Portable zip:** extract it anywhere and run `network_analyser.exe`. Keep `oui.txt` next to
the exe for MAC-vendor names.

**Packet capture (Npcap):**
1. Download and run the installer from <https://npcap.com/#download>.
2. Keep the defaults. Leave **"Restrict Npcap driver's access to Administrators only"**
   unticked; otherwise start Network Analyser as administrator.
3. Restart Network Analyser. Without Npcap every other tab still works, and the capture tab
   shows a short message instead.

**Serial ports:** USB adapters appear as `COM3`, `COM4`, and so on (see Device Manager → Ports
(COM & LPT)). Windows installs drivers for FTDI and most CP210x adapters automatically. For
CH340/CH341 or Prolific PL2303, install the driver from the chip vendor. A COM port can be open
in only one program at a time.

**Command line:** `--cli` and `--portscan` output appears in the console you started it from:
```powershell
& "$env:ProgramFiles\Network Analyser\network_analyser.exe" --portscan example.com top
```
If you chose *Install for me only*, the path is under `%LOCALAPPDATA%\Programs` instead.

## Updates

A few seconds after starting, the app checks GitHub for a newer release; the header shows
**v1.2.0 · Check for updates**, **Up to date ✓** or a green **⬆ Update to x.y.z** button.
The button opens the release notes and **Update now**, which downloads the right file for
how the app was installed, verifies it against the release's `SHA256SUMS.txt`, installs it
and restarts the app with the same options:

| Installed with | What *Update now* does |
|---|---|
| Windows installer | Runs the new setup silently (UAC prompt for an all-users install); it restarts the app |
| Windows zip | Replaces `network_analyser.exe` next to the old one |
| macOS `.dmg` | Replaces `/Applications/Network Analyser.app` |
| `.deb` / `.rpm` | Installs the new package through `pkexec` (password prompt) and keeps packet-capture rights |
| Linux tarball | Replaces the binary (password prompt only for a system-wide install) and keeps packet-capture rights |
| Built from source | Shows the release page instead |

Turn the automatic check off with `--no-update-check` or `NETWORK_ANALYSER_NO_UPDATE_CHECK=1`
(useful for kiosks); `network_analyser --check-update` checks from the command line.

## Build from source

Install Rust with [rustup](https://rustup.rs) (stable toolchain) on every platform, then follow
the steps for your OS.

**Debian / Ubuntu**
```sh
./.github/linux-deps.sh          # same build dependencies CI uses (includes libpcap-dev)
cargo build --release
./target/release/network_analyser --windowed
```

**Fedora**
```sh
sudo dnf install gcc clang pkg-config libxkbcommon-devel libxkbcommon-x11-devel \
  libxcb-devel libX11-devel wayland-devel wayland-protocols-devel vulkan-loader-devel \
  fontconfig-devel freetype-devel libzstd-devel openssl-devel libpcap-devel
cargo build --release
```

**Arch**
```sh
sudo pacman -S --needed base-devel clang libxkbcommon-x11 libxcb wayland wayland-protocols \
  vulkan-icd-loader fontconfig freetype2 zstd openssl libpcap
cargo build --release
```

**macOS**
```sh
xcode-select --install           # compilers; libpcap ships with macOS
cargo build --release
```

**Windows**
1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   with the **Desktop development with C++** workload, then rustup.
2. Download the [Npcap SDK](https://npcap.com/#download) and extract it, e.g. to `C:\npcap-sdk`.
3. Build in PowerShell:
   ```powershell
   $env:LIBPCAP_LIBDIR = "C:\npcap-sdk\Lib\x64"
   $env:LIBPCAP_VER = "1.10.0"
   cargo build --release
   ```
   The Npcap SDK is needed only for linking. `wpcap.dll` is delay-loaded, so the exe also runs on
   machines without Npcap.

Run the tests with `cargo test`. Serial and Modbus RTU tests use pseudo-terminals on Unix; the
BPF filter test is skipped when Npcap is not installed.

## Releasing

CI (`.github/workflows/ci.yml`) runs fmt, clippy and tests on Linux, macOS and Windows
for every push and PR. To publish a release:

```sh
# bump `version` in Cargo.toml first, commit, then:
git tag v1.2.0 && git push origin v1.2.0
```

`.github/workflows/release.yml` refreshes the MAC-vendor list, builds the
`.deb`/`.rpm`/`.tar.gz` (with `install.sh`), a universal macOS `.dmg`, and a Windows
`setup.exe` (Inno Setup, `packaging/windows/installer.iss`) plus a portable `.zip`, and publishes them
with `SHA256SUMS.txt` as a GitHub Release. The tag must match the Cargo.toml version.

## Run

```sh
network_analyser                # fullscreen (F11 toggles)
network_analyser --kiosk        # locked fullscreen, no decorations, F11 disabled
network_analyser --windowed     # normal window
network_analyser --kiosk --scan # start scanning the local subnet on launch
network_analyser --cli [RANGE]  # headless, prints a table
network_analyser --tool dns     # open a tool (lan, gateway, traceroute, dns, rdns, dhcp, wol,
                                # ports, capture, modbus, serial, netconfig, publicip, geoip, base64,
                                # snmp, ntp, sftp, dhcp-client, dns-client, can, profinet, bacnet,
                                # opcua, mqtt, websocket, pcap, decode, streams, http,
                                # handshake, dns-monitor, packet-stats, …)
network_analyser --open trace.pcapng             # open a capture file
network_analyser --pcap trace.pcapng http        # headless: info, packets, decode N, streams, follow N,
                                # http, http-body N, handshakes, dns, stats (-f BPF, -d DISPLAY-FILTER)
network_analyser --capture eth0 -t 30 -w out.pcap -f 'port 502'   # headless live capture
network_analyser --dns example.com MX @1.1.1.1   # headless DNS query (an IP = PTR lookup)
network_analyser --trace 8.8.8.8                 # headless traceroute
network_analyser --gateway      # headless gateway / NAT / DNS report
network_analyser --netconfig    # interfaces, routes, DNS servers
network_analyser --tls example.com:443          # certificate and TLS version scan
network_analyser --svc 10.0.0.5 top             # service and version detection
network_analyser --dnscheck example.com         # DNS / mail security report
network_analyser --wifi         # nearby Wi-Fi networks and channel advice
network_analyser --wol AA:BB:CC:DD:EE:FF [BROADCAST]
network_analyser --portscan example.com,10.0.0.0/30 top,8000-8100   # headless port scan
network_analyser --snmp 10.0.0.1 walk ifDescr  # SNMP summary / get / walk / v3 / check
network_analyser --ntp pool.ntp.org             # NTP offset, delay, stratum
network_analyser --ssh user@host                # SSH algorithms, host key, auth methods
network_analyser --dnsbench 1.1.1.1 9.9.9.9     # resolver benchmark and checks
network_analyser --dhcp-client eth0             # full DHCP exchange from a test MAC
network_analyser --can can0                     # candump-style monitor (or slcan:/dev/ttyACM0)
network_analyser --profinet eth0                # PROFINET DCP Identify All
network_analyser --bacnet --objects             # BACnet/IP Who-Is and device details
network_analyser --opcua opc.tcp://plc:4840 browse
network_analyser --opcua opc.tcp://plc:4840 --policy Basic256Sha256 --mode encrypt --user op --password …
network_analyser --mqtt mqtts://broker:8883 'sensors/#' 30
network_analyser --mqtt broker:8883 '#' 30 --ca ca.pem --cert client.pem --key client.key
network_analyser --ws wss://echo.websocket.org hello
network_analyser --list-ifaces  # capture interfaces
network_analyser --list-serial  # serial ports
network_analyser --update-oui   # refresh MAC-vendor DB (curl) -> ~/.local/share/network_analyser/oui.txt
```

Ranges: `192.168.1.0/24` (/16–/32), `10.0.0.5-40`, `10.0.0.5-10.0.1.9`, or a single IP.

## Keys

Text boxes: Enter runs the box's action (scan, connect, read, send…), Ctrl+U clears,
Ctrl+V pastes.

| Key | Action |
|---|---|
| Alt+↑ / Alt+↓ | Previous / next tool |
| Ctrl+B (⌘B on macOS) | Show / hide the sidebar |
| F5 / Ctrl+R / Enter in range box | Start / stop LAN scan |
| Ctrl+F | Focus search (Esc clears it, Esc again leaves the box) |
| F6 | Toggle live-only / all addresses |
| Ctrl+E | Export CSV to `~/network-scan-<timestamp>.csv` |
| F11 | Toggle fullscreen (not in kiosk) |
| Esc | Quit dialog (Enter = quit, Esc = cancel) |
| Ctrl+Q (⌘Q on macOS) | Quit immediately |
| ✕ Quit button | Quit dialog |

Click a row to open the details panel. Click a column header to sort (ascending →
descending → back to IP order; empty values always last).

Search matches IP, any hostname, MAC, vendor, device, OS, HTTP title/server, UPnP
info, port numbers, service names and banners. Every space-separated term must
match, so `raspberry 22` finds Raspberry Pis with SSH open.

## Layout

- `src/main.rs` – CLI flags, window/kiosk setup, key bindings, headless modes
- `src/shell.rs` – root view: header, segment sidebar, update and quit dialogs
- `src/tools.rs` – tool registry: segments, names, `--tool` slugs, view construction
- `src/cli_tools.rs` – headless `--dns`, `--trace`, `--gateway`, `--netconfig`, `--wol`
- `src/gateway.rs`, `src/gateway_view.rs` – gateway / NAT-PMP / UPnP-IGD / DNS health
- `src/traceroute.rs`, `src/trace_view.rs` – ping-based traceroute
- `src/dns.rs`, `src/dns_view.rs` – DNS client (all record types, EDNS/DNSSEC, TCP fallback), lookup and reverse tools
- `src/dhcp.rs`, `src/dhcp_view.rs` – DHCP parsing / DISCOVER frames, DHCP analyser
- `src/wol.rs`, `src/wol_view.rs` – Wake-on-LAN
- `src/netconfig.rs`, `src/netconfig_view.rs` – interfaces, routes, neighbours
- `src/webapi.rs`, `src/utils_view.rs` – opt-in online lookups; Public IP, Geolocation, Base64
- `src/settings.rs` – persistent `settings.json`
- `src/tls.rs`, `src/tls_view.rs` – TLS scanner (rustls + x509-parser, legacy probe, STARTTLS)
- `src/svcdetect.rs`, `src/audit.rs`, `src/audit_view.rs` – service / version detection, port audit rules and baselines
- `src/firewall.rs`, `src/firewall_view.rs` – firewall tests, rogue DHCP tester
- `src/arpwatch.rs`, `src/dnscheck.rs`, `src/anomaly.rs`, `src/watch_view.rs` – ARP spoof detection, DNS security, anomaly detection
- `src/monitor.rs`, `src/monitor_view.rs` – probe engine and statistics (latency, jitter, loss, uptime)
- `src/throughput.rs`, `src/bandwidth.rs`, `src/wifi.rs`, `src/perf_view.rs` – throughput server/client, interface counters, Wi-Fi scanning
- `src/widgets.rs` – palette, buttons, chips, text input, table cells
- `src/ui.rs` – LAN Scan tab (toolbar, table, details, status bar)
- `src/portscan.rs`, `src/portscan_view.rs` – remote TCP port scanner and its tab
- `src/capture.rs`, `src/pcapfile.rs` – live capture thread; native pcap / pcapng reader and writer
- `src/dissect.rs`, `src/appproto.rs` – packet dissector; application protocol identification and decoding
- `src/session.rs` – capture session shared by the packet-analysis tools
- `src/streams.rs`, `src/httpstream.rs` – TCP tracking, handshakes and reassembly; HTTP reconstruction
- `src/dnsmon.rs`, `src/pktstats.rs` – DNS transactions; packet statistics
- `src/capture_view.rs`, `src/flows_view.rs`, `src/dnsmon_view.rs`, `src/pktstats_view.rs` – packet-analysis views
- `src/pcap_cli.rs` – headless `--pcap` and `--capture`
- `src/serial.rs`, `src/serial_view.rs` – serial enumeration, monitor thread, baud detection, Serial tab
- `src/modbus.rs`, `src/modbus_view.rs` – Modbus RTU/TCP framing, CRC, master thread, scans, passive decoder, Modbus tab
- `src/scanner.rs` – scan engine (own thread + tokio), fingerprinting
- `src/probes.rs` – ping, TCP, banners/HTTP, mDNS, NetBIOS, SSDP/UPnP, rDNS
- `src/netinfo.rs` – interfaces, OUI vendors, ranges, port names
- `src/platform.rs` – per-OS gateway / ARP / MAC / directories (Linux `/proc`, macOS & Windows `route`/`arp`/`ifconfig`/`ipconfig`)
- `build.rs` – embeds the icon into the Windows `.exe`, delay-loads Npcap's `wpcap.dll`
- `assets/` – icon (PNG/ICO), `.desktop` file

`libc` is pinned to 0.2.186 (and tokio to 1.52) in `Cargo.lock`. Newer `libc` removed
`ENOATTR`, which breaks `xattr 0.2.3`, a dependency gpui 0.2.2 pulls in. Keep the
lockfile when updating (CI builds with `--locked`).

## License

MIT, see [LICENSE](LICENSE).
