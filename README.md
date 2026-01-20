# curl-portscan.sh

A port scanner using curl. Useful for boxes that don't have netcat, nmap, or other scanning tools. Almost every host has curl because it's not typically viewed as malicious.

It's no replacement for nmap, but gets the job done!

## Usage

```
./curl-portscan.sh -t <target> -p <ports> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `-t <target>` | Target host/IP/CIDR/range (e.g., `192.168.1.0/24` or `192.168.1.1-192.168.1.10`) |
| `-p <ports>` | Ports to scan (e.g., `1-1024,1055,3333-4444` or `all` for 1-65535) |
| `-m <timeout>` | Curl timeout in seconds (default: 1) |
| `-v` | Verbose output (shows closed/filtered ports) |
| `-d <delay>` | Delay between port scans in seconds |
| `-r` | Randomize port scanning order |
| `-f` | Fast scan using common ports from `/etc/services` |
| `-l <logfile>` | Log results to a file |
| `-D` | Detect DNS servers that catch unresolvable hosts |
| `-h` | Display help message |

### Examples

```bash
# Scan common ports on a single host
./curl-portscan.sh -t 192.168.1.1 -p 1-1024

# Fast scan using common ports
./curl-portscan.sh -t example.com -f

# Scan a CIDR range with logging
./curl-portscan.sh -t 192.168.1.0/24 -p 22,80,443 -l results.txt

# Scan IP range with randomized ports and delay
./curl-portscan.sh -t 192.168.1.1-192.168.1.10 -p 1-1000 -r -d 1

# Verbose scan with DNS catchall detection
./curl-portscan.sh -t example.com -p 1-1024 -v -D
```

### One-liner

Scanning can also be done via a one-liner to avoid writes to disk:

```bash
for i in {1..1024}; do curl -s -m 1 localhost:$i >/dev/null; if [ ! $? -eq 7 ] && [ ! $? -eq 28 ]; then echo open: $i; fi; done
```

## Features

- **CIDR Support** - Scan entire subnets (e.g., `192.168.1.0/24`)
- **IP Range Support** - Scan IP ranges (e.g., `192.168.1.1-192.168.1.10`)
- **Fast Scan Mode** - Quickly scan common ports from `/etc/services`
- **Service Detection** - Shows service names from `/etc/services`
- **DNS Catchall Detection** - Detects DNS servers that resolve non-existent hosts
- **Randomized Scanning** - Randomize port order to avoid detection
- **Scan Delay** - Add delays between ports for stealth
- **Logging** - Save results to file in nmap-style format
- **Color Output** - Green for open, red for closed, yellow for filtered
- **nmap-style Output** - Familiar output format

## Why curl?

- **Living off the land** - No need to install extra tools
- **Always available** - curl is nearly always installed on Linux systems
- **Not flagged** - Unlike nmap/netcat, curl isn't typically removed by security-conscious sysadmins
- **Sometimes you use what you have** - When the right tool isn't available, improvise

