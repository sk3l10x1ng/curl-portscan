#!/bin/bash

# Portscans a host using curl, because its almost always available.
# It is no replacement for nmap, but gets the job done!


VERSION="1.0"
DEFAULT_PORTS="1-1024"
DEFAULT_TIMEOUT=1
declare -A PORTINDEX  # Initialize as an associative array
VERBOSE=0
DEFAULT_DELAY=0
LOG_FILE=""
RANDOMIZE=0
FAST_SCAN=0
DNS_DETECT=0
DNS_CHECK_HOST="thishostdefinitelydoesnotexist12345"
GENERATE_SHORT=0
SCAN_START_TIME=""
declare -a OPEN_PORTS=()
declare -a CLOSED_PORTS=()
declare -a FILTERED_PORTS=()

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo
    echo -e "Starting curl-portscan ${VERSION} ( https://github.com/sk3l10x1ng/curl-portscan ) at $(date '+%Y-%m-%d %H:%M %Z')"
}

usage() {
    echo "usage: $0 -t <target> -p <ports> [-m <timeout>] [-h]"
    echo -e "\t-t <target>\t-- target host/IP/CIDR/range (e.g., 192.168.1.0/24 or 192.168.1.1-192.168.1.10)"
    echo -e "\t-p <ports>\t-- ports to scan. ex: 1-1024,1055,3333-4444"
    echo -e "\t-m <timeout>\t-- curl timeout in seconds"
    echo -e "\t-v\t\t-- toggle verbose output"
    echo -e "\t-d <delay>\t-- delay between port scans in seconds"
    echo -e "\t-r\t\t-- randomize port list"
    echo -e "\t-f\t\t-- fast scan using /etc/services for common ports"
    echo -e "\t-l <logfile>\t-- log results to a file"
    echo -e "\t-D\t\t-- detect DNS servers that catch unresolvable hosts"
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

# Convert IP to integer
ip_to_int() {
    local ip=$1
    local a b c d
    IFS=. read -r a b c d <<< "$ip"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# Convert integer to IP
int_to_ip() {
    local int=$1
    echo "$(( (int >> 24) & 255 )).$(( (int >> 16) & 255 )).$(( (int >> 8) & 255 )).$(( int & 255 ))"
}

# Expand CIDR notation to list of IPs
expand_cidr() {
    local cidr=$1
    local ip mask

    IFS='/' read -r ip mask <<< "$cidr"

    # If no mask specified, it's a single IP
    if [ -z "$mask" ]; then
        echo "$ip"
        return
    fi

    local ip_int=$(ip_to_int "$ip")
    local netmask=$(( 0xFFFFFFFF << (32 - mask) & 0xFFFFFFFF ))
    local network=$(( ip_int & netmask ))
    local broadcast=$(( network | ~netmask & 0xFFFFFFFF ))

    # For /31 and /32, include all addresses
    if [ "$mask" -ge 31 ]; then
        for (( i=network; i<=broadcast; i++ )); do
            int_to_ip $i
        done
    else
        # Skip network and broadcast addresses
        for (( i=network+1; i<broadcast; i++ )); do
            int_to_ip $i
        done
    fi
}

# Expand IP range (e.g., 192.168.1.1-192.168.1.10)
expand_ip_range() {
    local range=$1
    local start_ip end_ip

    if [[ "$range" == *"-"* ]] && [[ "$range" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        IFS='-' read -r start_ip end_ip <<< "$range"
        local start_int=$(ip_to_int "$start_ip")
        local end_int=$(ip_to_int "$end_ip")

        if [ "$start_int" -gt "$end_int" ]; then
            echo "[-] Invalid IP range: start > end" >&2
            return 1
        fi

        for (( i=start_int; i<=end_int; i++ )); do
            int_to_ip $i
        done
    elif [[ "$range" == *"/"* ]]; then
        expand_cidr "$range"
    else
        echo "$range"
    fi
}

# Detect DNS servers that catch unresolvable hosts
detect_dns_catchall() {
    local target=$1
    local test_host="${DNS_CHECK_HOST}.${target}"

    # Try to resolve a definitely non-existent subdomain
    if host "$test_host" >/dev/null 2>&1; then
        return 0  # DNS is catching unresolvable hosts
    fi

    # Also try with curl to see if we get a response
    if curl -s -m 2 "http://${test_host}" >/dev/null 2>&1; then
        local exit_code=$?
        if [ "$exit_code" -ne 6 ] && [ "$exit_code" -ne 7 ] && [ "$exit_code" -ne 28 ]; then
            return 0  # Got a response for non-existent host
        fi
    fi

    return 1  # DNS is behaving normally
}

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
	-D) DNS_DETECT=1
	    ;;
	-*) echo "ERROR: Unknown option: $1"
	    exit 1
	    ;;
	*) echo "ERROR: Unknown argument: $1"
	   exit 1
	   ;;
    esac

    shift
done

# Make sure a host is set!
if [ ! "$target" ]; then
    echo "ERROR: No target specified. Use -t <target>"
    exit 1
fi

# Expand target to list of IPs (supports CIDR and IP ranges)
targets=$(expand_ip_range "$target")
if [ $? -ne 0 ]; then
    echo "Failed to expand target: $target"
    exit 1
fi
target_count=$(echo "$targets" | wc -w)

# Fast scan using /etc/services for common ports
if [ $FAST_SCAN -eq 1 ]; then
    ports=$(grep -Eo '^[a-zA-Z0-9_-]+\s+[0-9]{1,5}/tcp' /etc/services | awk '{print $2}' | cut -d/ -f1 | sort -nu | tr '\n' ' ')
else
    # Make sure port range only has numbers, hyphens, and commas
    if [[ ! "$ports" =~ ^[0-9,-]+$ ]]; then
        echo "ERROR: Invalid port specification: $ports"
        exit 1
    fi

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
                echo "ERROR: Invalid port range: ${tmp[0]}-${tmp[1]}"
                exit 1
            fi

            token=$(seq -s ' ' "${tmp[0]}" "${tmp[1]}")
        fi
        out="$out $token"
    done

    # uniq ports list
    ports=$(echo "$out" | tr ' ' '\n' | sort -nu)
fi

# Randomize port list if requested
if [ $RANDOMIZE -eq 1 ]; then
    ports=$(echo "$ports" | tr ' ' '\n' | shuf | tr '\n' ' ')
fi

populate_port_index

# Count ports for display
portcount=$(echo "$ports" | wc -w)

# Record scan start time
SCAN_START_TIME=$(date +%s.%N)

# Print banner
print_banner

# Build command line representation for log
PORTS_DISPLAY=$(echo "$ports" | tr '\n' ',' | sed 's/^,//;s/,$//')
CMD_LINE="$0 -t $target -p ${PORTS_DISPLAY} -m $timeout"
[ $VERBOSE -eq 1 ] && CMD_LINE="$CMD_LINE -v"
[ $RANDOMIZE -eq 1 ] && CMD_LINE="$CMD_LINE -r"
[ $FAST_SCAN -eq 1 ] && CMD_LINE="$CMD_LINE -f"
[ $DNS_DETECT -eq 1 ] && CMD_LINE="$CMD_LINE -D"
[ "$delay" -gt 0 ] && CMD_LINE="$CMD_LINE -d $delay"

# Initialize logging with header (nmap-style)
if [ "$LOG_FILE" ]; then
    echo "# curl-portscan ${VERSION} scan initiated $(date '+%a %b %d %H:%M:%S %Y') as: ${CMD_LINE} -l ${LOG_FILE}" >> "$LOG_FILE"
fi

# Resolve hostname to IP
resolve_host() {
    local host=$1
    local ip=""

    # Check if it's already an IP address
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$host"
        return
    fi

    # Try to resolve using getent (most portable)
    ip=$(getent hosts "$host" 2>/dev/null | awk '{print $1}' | head -1)
    if [ -n "$ip" ]; then
        echo "$ip"
        return
    fi

    # Fallback to host command
    ip=$(host "$host" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
    if [ -n "$ip" ]; then
        echo "$ip"
        return
    fi

    echo ""
}

# Scan function for a single target (nmap-style output)
scan_target() {
    local current_target=$1
    local open_count=0
    local closed_count=0
    local filtered_count=0
    local host_start_time=$(date +%s.%N)
    local resolved_ip=""

    # Reset port arrays
    OPEN_PORTS=()
    CLOSED_PORTS=()
    FILTERED_PORTS=()

    # DNS catchall detection
    if [ $DNS_DETECT -eq 1 ]; then
        if detect_dns_catchall "$current_target"; then
            echo -e "${YELLOW}WARNING:${NC} DNS server appears to catch unresolvable hosts."
            echo "Results may include false positives."
            if [ "$LOG_FILE" ]; then
                echo "# WARNING: DNS catchall detected for $current_target" >> "$LOG_FILE"
            fi
        fi
    fi

    # Resolve hostname
    resolved_ip=$(resolve_host "$current_target")

    echo
    if [ -n "$resolved_ip" ] && [ "$resolved_ip" != "$current_target" ]; then
        echo -e "Nmap scan report for ${current_target} (${resolved_ip})"
        [ "$LOG_FILE" ] && echo "Nmap scan report for ${current_target} (${resolved_ip})" >> "$LOG_FILE"
    else
        echo -e "Nmap scan report for ${current_target}"
        [ "$LOG_FILE" ] && echo "Nmap scan report for ${current_target}" >> "$LOG_FILE"
    fi
    echo "Host is up."
    [ "$LOG_FILE" ] && echo "Host is up." >> "$LOG_FILE"
    echo

    # Scan all ports first, collect results
    for port in $ports; do
        service=$(get_port_index "$port")
        curl -s -m "$timeout" "${current_target}":"${port}" > /dev/null
        local exit_code=$?

        case $exit_code in
            6) # Failed to resolve
                echo -e "${RED}Failed to resolve \"${current_target}\".${NC}"
                [ "$LOG_FILE" ] && echo "Failed to resolve \"${current_target}\"." >> "$LOG_FILE"
                return 1
                ;;
            7) # Failed to connect - port closed
                CLOSED_PORTS+=("${port}|closed|${service}")
                closed_count=$((closed_count+1))
                ;;
            28) # Operation Timeout - port filtered
                FILTERED_PORTS+=("${port}|filtered|${service}")
                filtered_count=$((filtered_count+1))
                ;;
            *) # Port is open
                OPEN_PORTS+=("${port}|open|${service}")
                open_count=$((open_count+1))
                ;;
        esac

        # Delay between port scans
        if [ "$delay" -gt 0 ]; then
            sleep "$delay"
        fi
    done

    # Calculate not shown ports
    local not_shown=$((closed_count + filtered_count))

    # Print summary of not shown ports
    if [ $not_shown -gt 0 ] && [ $VERBOSE -eq 0 ]; then
        local not_shown_msg=""
        if [ $closed_count -gt 0 ] && [ $filtered_count -gt 0 ]; then
            not_shown_msg="Not shown: ${closed_count} closed tcp ports (conn-refused), ${filtered_count} filtered tcp ports (no-response)"
        elif [ $closed_count -gt 0 ]; then
            not_shown_msg="Not shown: ${closed_count} closed tcp ports (conn-refused)"
        elif [ $filtered_count -gt 0 ]; then
            not_shown_msg="Not shown: ${filtered_count} filtered tcp ports (no-response)"
        fi
        echo "$not_shown_msg"
        [ "$LOG_FILE" ] && echo "$not_shown_msg" >> "$LOG_FILE"
    fi

    # Print port table header
    printf "%-10s %-10s %s\n" "PORT" "STATE" "SERVICE"
    [ "$LOG_FILE" ] && printf "%-10s %-10s %s\n" "PORT" "STATE" "SERVICE" >> "$LOG_FILE"

    # Print open ports
    for entry in "${OPEN_PORTS[@]}"; do
        IFS='|' read -r port state service <<< "$entry"
        printf "%-10s ${GREEN}%-10s${NC} %s\n" "${port}/tcp" "$state" "$service"
        [ "$LOG_FILE" ] && printf "%-10s %-10s %s\n" "${port}/tcp" "$state" "$service" >> "$LOG_FILE"
    done

    # Print closed/filtered ports in verbose mode
    if [ $VERBOSE -eq 1 ]; then
        for entry in "${CLOSED_PORTS[@]}"; do
            IFS='|' read -r port state service <<< "$entry"
            printf "%-10s ${RED}%-10s${NC} %s\n" "${port}/tcp" "$state" "$service"
            [ "$LOG_FILE" ] && printf "%-10s %-10s %s\n" "${port}/tcp" "$state" "$service" >> "$LOG_FILE"
        done
        for entry in "${FILTERED_PORTS[@]}"; do
            IFS='|' read -r port state service <<< "$entry"
            printf "%-10s ${YELLOW}%-10s${NC} %s\n" "${port}/tcp" "$state" "$service"
            [ "$LOG_FILE" ] && printf "%-10s %-10s %s\n" "${port}/tcp" "$state" "$service" >> "$LOG_FILE"
        done
    fi

    echo
    [ "$LOG_FILE" ] && echo "" >> "$LOG_FILE"

    return 0
}

# Main scan loop - iterate over all targets
hosts_up=0
hosts_down=0
for current_target in $targets; do
    if scan_target "$current_target"; then
        hosts_up=$((hosts_up+1))
    else
        hosts_down=$((hosts_down+1))
    fi
done

# Calculate total scan time
SCAN_END_TIME=$(date +%s.%N)
SCAN_DURATION=$(echo "scale=2; ($SCAN_END_TIME - $SCAN_START_TIME)" | bc 2>/dev/null || echo "0")

# Print final summary (nmap-style)
echo "curl-portscan done: ${target_count} IP address(es) (${hosts_up} host(s) up) scanned in ${SCAN_DURATION} seconds"

# Final summary to log (nmap-style)
if [ "$LOG_FILE" ]; then
    echo "# curl-portscan done at $(date '+%a %b %d %H:%M:%S %Y') -- ${target_count} IP address(es) (${hosts_up} host(s) up) scanned in ${SCAN_DURATION} seconds" >> "$LOG_FILE"
fi
