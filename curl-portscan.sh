#!/bin/bash

# Portscans a host using curl, because its almost always available.
# It is no replacement for nmap, but gets the job done!
#

DEFAULT_PORTS="1-1024"
DEFAULT_TIMEOUT=1
PORTINDEX=""
VERBOSE=0
DEFAULT_DELAY=2
LOG_FILE=""
RANDOMIZE=0
FAST_SCAN=0
DNS_DETECT=0


echo

usage() {
    echo "usage: $0 -t <target> -p <ports> [-m <timeout>] [-h]"
    echo -e "\t-t <target>\t-- target host/IP/CIDR range to scan"
    echo -e "\t-p <ports>\t-- ports to scan. ex: 1-1024,1055,3333-4444"
    echo -e "\t-m <timeout>\t-- curl timeout in seconds"
    echo -e "\t-v\t\t-- toggle verbose output"
    echo -e "\t-d <delay>\t-- delay between port scans in seconds"
    echo -e "\t-r\t\t-- randomize port list"
    echo -e "\t-f\t\t-- fast scan using /etc/services for common ports"
    echo -e "\t-l <logfile>\t-- log results to a file"
    echo -e "\t-h\t\t-- display this help message"
}

populate_port_index() {
    if [ ! -r "/etc/services" ]; then
	return
    fi

    services=$(grep "[0-9]/tcp" /etc/services)

    while read -r line; do
	tmp=($line)

	port=$(echo "${tmp[1]}" | cut -d / -f 1)
	service=${tmp[0]}

	PORTINDEX[$port]=$service
    done < <(echo "$services")
}

# Print service name if it exists in PORTINDEX array or unknown if it doesn't
get_port_index() {
    service=${PORTINDEX[$1]}

    if [ ! "$service" ]; then
	service="unknown"
    fi

    echo $service
}
y

# set defaults
timeout=$DEFAULT_TIMEOUT
ports=$DEFAULT_PORTS
delay=$DEFAULT_DELAY

# CLI args.
if [ $# -eq 0 ]; then
    usage
    exit 1
fi

while [ $# -gt 0 ]; do
    case $1 in
	-h) usage;
	    exit 0
	    ;;
	-t) target=$2
	    shift
	    ;;
	-p) # Deal with ports
	    if [ "$2" == "all" ]; then
		ports="1-65535"
	    else
		ports=$2
	    fi
	    shift
	    ;;
	-m) timeout=$2
	    shift
	    ;;
	-v) VERBOSE=$((VERBOSE+1))
	    ;;
	-d) delay=$2
	    shift
	    ;;
	-r) RANDOMIZE=1
	    ;;
	-f) FAST_SCAN=1
	    ;;
	-l) LOG_FILE=$2
	    shift
	    ;;
	-*) echo "[-] Unknown flag: $1"
	    echo "[-] Exiting."
	    exit 1
	    ;;
	*) echo "[-] Unknown argument: $1"
	   echo "[-] Exiting."
	   exit 1
	   ;;
    esac

    shift
done

# Make sure a host is set!
if [ ! "$target" ]; then
    echo "[-] Syntax Error. Must specify a host with -t"
    echo "[-] Exiting"
    exit 1
fi

# Make sure port range only has numbers, hyphens, and commas
if [[ ! "$ports" =~ ^[0-9,-]+$ ]]; then
    echo "[-] Syntax Error. Invalid port range: $ports"
    echo "[-] Exiting"
    exit 1
fi

# replace commas with space to make life easier on @dmfroberson
ports=$(echo "$ports" | tr , ' ')

# Initialize out variable
out=""

# deal with ranges of ports
for token in $ports; do
    if [[ $token == *"-"* ]]; then
	token=$(echo "$token" | tr - ' ')

	# Verify that the range makes sense
	tmp=($token)
	if [ "${tmp[0]}" -ge "${tmp[1]}" ]; then
	    echo "[-] Syntax error. Invalid port range: ${tmp[0]}-${tmp[1]}"
	    echo "[-] Exiting."
	    exit 1
	fi

	token=$(seq -s ' ' "${tmp[0]}" "${tmp[1]}")
    fi
    out="$out $token"
done

# uniq ports list
echo -n "[+] Building list of ports.. "
ports=$(echo "$out" | tr ' ' '\n' | sort -nu)
echo "Done."

populate_port_index

# Fast scan using /etc/services for common ports
if [ $FAST_SCAN -eq 1 ]; then
    ports=$(grep -Eo '^[0-9]+' /etc/services | sort -nu | tr '\n' ' ')
fi

# Randomize port list if requested
if [ $RANDOMIZE -eq 1 ]; then
    ports=$(echo "$ports" | tr ' ' '\n' | shuf | tr '\n' ' ')
fi

# Do the scan.
portcount=$(echo "$ports" | wc -w)
echo [+] Scanning "$portcount" ports on "$target"
echo

count=0
for port in $ports; do
    service=$(get_port_index "$port")
    curl -s -m "$timeout" "${target}":"${port}" > /dev/null

    case $? in
	6) # Failed to resolve
	    echo "[-] Unable to resolve host: $target"
	    echo "[-] Exiting."
	    exit 1
	    ;;
	7) # Failed to connect
	    if [ $VERBOSE -eq 1 ]; then
		echo "[*] Port ${port}/${service} -- Failed to connect"
	    fi
	    continue
	    ;;
	28) # Operation Timeout
	    if [ $VERBOSE -eq 1 ]; then
		echo "[*] Port ${port}/${service} -- Operation Timeout"
	    fi
	    continue
	    ;;
    esac

    echo "[+] Port ${port}/${service} appears to be open."
    if [ "$LOG_FILE" ]; then
        echo "[+] Port ${port}/${service} appears to be open." >> "$LOG_FILE"
    fi

    count=$((count+1))
    sleep "$delay"
done

echo
echo "[+] Done. $count ports open."
if [ "$LOG_FILE" ]; then
    echo "[+] Done. $count ports open." >> "$LOG_FILE"
fi
