#!/bin/sh
### BEGIN INIT INFO
#
# @@@@@@@   @@@@@@@@  @@@       @@@   @@@@@@@  @@@@@@@@  @@@@@@@    @@@@@@    @@@@@@@@
# @@@@@@@@  @@@@@@@@  @@@       @@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@@
# @@!  @@@  @@!       @@!       @@!  !@@       @@!       @@!  @@@  @@!  @@@  !@@
# !@!  @!@  !@!       !@!       !@!  !@!       !@!       !@!  @!@  !@!  @!@  !@!
# @!@!!@!   @!!!:!    @!!       !!@  !@!       @!!!:!    @!@!!@!   @!@  !@!  !@! @!@!@
# !!@!@!    !!!!!:    !!!       !!!  !!!       !!!!!:    !!@!@!    !@!  !!!  !!! !!@!!
# !!: :!!   !!:       !!:       !!:  :!!       !!:       !!: :!!   !!:  !!!  :!!   !!:
# :!:  !:!  :!:        :!:      :!:  :!:       :!:       :!:  !:!  :!:  !:!  :!:   !::
# ::   :::   :: ::::   :: ::::   ::   ::: :::   ::       ::   :::  ::::: ::   ::: ::::
#  :   : :  : :: ::   : :: : :  :     :: :: :   :         :   : :   : :  :    :: :: :
#
# gatekeeper firewall control script v1.0.1
#
#
# Provides:          iptables
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Firewall Script
# Description:       raspberry pi 4 hardening script for iptables (v1.0.0)
### END INIT INFO

rf_error () {
    if [ -n "$1" ]; then
      echo "$1"
    else
      echo "an unknown error occurred."
    fi
    exit 1
}

init() {

  if [ $EUID -ne 0 ]; then
    rf_error "[ALERT] gatekeeper script must be run as root (current UID: $EUID)! <Aborting>"
  fi

  hash iptables 2>/dev/null  || { rf_error "[ALERT] gatekeeper script requires the iptables command but it's not available! <Aborting>"; }
  hash ip6tables 2>/dev/null || { rf_error "[ALERT] gatekeeper script requires the ip6tables command but it's not available! <Aborting>"; }
  hash ip 2>/dev/null        || { rf_error "[ALERT] gatekeeper script requires the IP command but it's not available! <Aborting>"; }

  MY_VERSION="1.0.1"
  MY_SERVER_IP4_ETH_0="$(ip addr show eth0  | grep 'inet ' | cut -f2 | awk '{ print $2}')"
  MY_SERVER_IP4_WLN_0="$(ip addr show wlan0 | grep 'inet ' | cut -f2 | awk '{ print $2}')"
  MY_SERVER_NETWORK="lo eth0 wlan0"
  MY_HOST_IP4_LOCALS="127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 10.0.0.0/8"
  MY_LOG_PREFIX_SSH="[gatekeeper/found/SSH] -- "
  MY_LOG_PREFIX_INP="[gatekeeper/block/INP] -- "
  MY_LOG_PREFIX_FWD="[gatekeeper/block/OUT] -- "
  MY_LOG_PREFIX_OUT="[gatekeeper/block/FWD] -- "
  Q9_DNS_SERVER="9.9.9.9 149.112.112.112"

  echo "Gatekeeper, Raspberry Pi Firewall Control Script v${MY_VERSION}"
  echo "created by RelicFrog team + friends"

  set -o errexit
}

configure_network() {

    iptables -A INPUT -i lo -j ACCEPT

    for adapter in ${MY_SERVER_NETWORK}
    do
        echo "allow outgoing network traffic for '${adapter}'"
        iptables -A OUTPUT -o "${adapter}" -j ACCEPT
    done

    for ip in ${MY_HOST_IP4_LOCALS}
    do
        echo "reject lo-traffic for non-loopback interface (lo0) '${ip}'"
        iptables -A INPUT  -d "${ip}" -j REJECT
        iptables -A OUTPUT -d "${ip}" -j REJECT
    done
}

configure_postrouting() {

    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
}

configure_input_chain() {

    # keep all established connections
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

    # allow incoming ssh from our network baseline (log every access succeeded)
    iptables -I INPUT -p tcp -m tcp --dport 22 -m state --state NEW -j LOG --log-level 4 --log-prefix "$MY_LOG_PREFIX_SSH"
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    # baseline configuration for incoming DNS traffic
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT # DNS/TCP
    iptables -A INPUT -p udp --dport 53 -j ACCEPT # DNS/UDP
    ip6tables -A INPUT -p tcp --dport 53 -j ACCEPT # DNS/TCP
    ip6tables -A INPUT -p udp --dport 53 -j ACCEPT # DNS/UDP

    # explicit allow pi-hole incoming dns requests (netbios, dns, m-dns ...)
    [ -z "$MY_SERVER_IP4_ETH_0" ] && echo "ignore eth0, missing ipv4 notation"  || iptables -A INPUT -s "${MY_SERVER_IP4_ETH_0}" -j ACCEPT
    [ -z "$MY_SERVER_IP4_WLN_0" ] && echo "ignore wlan0, missing ipv4 notation" || iptables -A INPUT -s "${MY_SERVER_IP4_WLN_0}" -j ACCEPT
    for ip in ${Q9_DNS_SERVER}
    do
        echo "allow DNS lookups (tcp, udp port 53) from q9-server '${ip}'"
        iptables -A INPUT  -s "${ip}" -j ACCEPT
    done

    iptables -A INPUT -p udp -m multiport --dport 137,138,139 -j ACCEPT # NetBIOS Name Service, Datagram Service, Session Service
    iptables -A INPUT -p tcp -m multiport --dport 80,443 -j ACCEPT # HTTP/HTTPS
    iptables -A INPUT -p tcp -m multiport --dport 953,5353,57621 -j ACCEPT # mDNS/DNS RNDC Service
    iptables -A INPUT -p udp -m multiport --dport 67,68,69 -j ACCEPT # DHCP

    iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT # ping reply
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT # ping request
    iptables -A INPUT -s 224.0.0.0/4 -j ACCEPT # allow multicast

    ip6tables -A INPUT -p udp -m multiport --dport 137,138,139 -j ACCEPT # NetBIOS Name Service, Datagram Service, Session Service
    ip6tables -A INPUT -p tcp -m multiport --dport 80,443 -j ACCEPT # HTTP/HTTPS
    ip6tables -A INPUT -p tcp -m multiport --dport 953,5353,57621 -j ACCEPT # mDNS/DNS RNDC Service
    ip6tables -A INPUT -p udp -m multiport --dport 67,68,69 -j ACCEPT # DHCP
    ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-reply -j ACCEPT # ping reply
    ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT # ping request

    # log+lock incoming traffic
    iptables -A INPUT -j LOG -m limit --limit 12/min --log-prefix "$MY_LOG_PREFIX_INP" --log-level 4
    iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
    ip6tables -A INPUT -j REJECT --reject-with icmp6-adm-prohibited
}

configure_output_chain() {

    # keep all established connections
    iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    ip6tables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

    # allow outgoing ssh from our network baseline
    iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    # explicit allow pi-hole outgoing dns requests (netbios, dns, m-dns ...)
    for ip in ${Q9_DNS_SERVER}
    do
        echo "allow DNS lookups (tcp, udp port 53) to q9-server '${ip}'"
        iptables -A OUTPUT -d "${ip}" -j ACCEPT
    done

    # allow dns/http/https
    iptables -A OUTPUT -p tcp -m tcp --sport 53:65535 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp -m udp --sport 53:65535 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -m multiport --dport 80,443  -j ACCEPT
    iptables -A OUTPUT -p udp -m multiport --dport 80,443 -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT # ping reply
    iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT # ping request
    iptables -A OUTPUT  -d 224.0.0.0/4 -j ACCEPT # allow multicast
    iptables -A OUTPUT -o eth0 -p udp --dport 631 -j REJECT # prevent print spam

    ip6tables -A OUTPUT -p tcp -m tcp --sport 53:65535 --dport 53 -j ACCEPT
    ip6tables -A OUTPUT -p udp -m udp --sport 53:65535 --dport 53 -j ACCEPT
    ip6tables -A OUTPUT -p tcp -m multiport --dport 80,443  -j ACCEPT
    ip6tables -A OUTPUT -p udp -m multiport --dport 80,443 -j ACCEPT
    ip6tables -A OUTPUT -p icmpv6 --icmpv6-type echo-reply -j ACCEPT # ping reply
    ip6tables -A OUTPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT # ping request
    ip6tables -A OUTPUT -o eth0 -p udp --dport 631 -j REJECT # prevent print spam

    # log+lock outgoing traffic
    iptables -A OUTPUT  -j LOG -m limit --limit 12/min --log-prefix "$MY_LOG_PREFIX_OUT" --log-level 4
    iptables -A OUTPUT -j REJECT --reject-with icmp-host-prohibited
    ip6tables -A OUTPUT -j REJECT --reject-with icmp6-adm-prohibited
}

configure_forward_chain() {

    # keep all established connections
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    ip6tables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

    # activate forward chain rules (add all new port clearance here!)
    iptables -A FORWARD -p tcp --dport  53 -j ACCEPT # DNS
    iptables -A FORWARD -p udp --dport  53 -j ACCEPT # DNS
    iptables -A FORWARD -p tcp --dport  80 -j ACCEPT # HTTP
    iptables -A FORWARD -p udp --dport 123 -j ACCEPT # NTP
    iptables -A FORWARD -p tcp --dport 443 -j ACCEPT # HTTPs
    iptables -A FORWARD -p tcp --dport 587 -j ACCEPT # submission
    iptables -A FORWARD -s 224.0.0.0/4 -d 224.0.0.0/4 -j ACCEPT

    ip6tables -A FORWARD -p tcp --dport  53 -j ACCEPT # DNS
    ip6tables -A FORWARD -p udp --dport  53 -j ACCEPT # DNS
    ip6tables -A FORWARD -p tcp --dport  80 -j ACCEPT # HTTP
    ip6tables -A FORWARD -p udp --dport 123 -j ACCEPT # NTP
    ip6tables -A FORWARD -p tcp --dport 443 -j ACCEPT # HTTPs
    ip6tables -A FORWARD -p tcp --dport 587 -j ACCEPT # submission

    # log+lock forwarded traffic
    iptables -A FORWARD -j LOG -m limit --limit 12/min --log-prefix "$MY_LOG_PREFIX_FWD" --log-level 4
    iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited
    ip6tables -A FORWARD -j REJECT --reject-with icmp6-adm-prohibited
}

configure_hardening() {

    # Prevent port scanning
    iptables -N PORTSCAN
    iptables -A PORTSCAN -p tcp --tcp-flags ACK,FIN FIN -j DROP
    iptables -A PORTSCAN -p tcp --tcp-flags ACK,PSH PSH -j DROP
    iptables -A PORTSCAN -p tcp --tcp-flags ACK,URG URG -j DROP
    iptables -A PORTSCAN -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
    iptables -A PORTSCAN -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    iptables -A PORTSCAN -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables -A PORTSCAN -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A PORTSCAN -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A PORTSCAN -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
    iptables -A PORTSCAN -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
    iptables -A PORTSCAN -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

    ip6tables -N PORTSCAN
    ip6tables -A PORTSCAN -p tcp --tcp-flags ACK,FIN FIN -j DROP
    ip6tables -A PORTSCAN -p tcp --tcp-flags ACK,PSH PSH -j DROP
    ip6tables -A PORTSCAN -p tcp --tcp-flags ACK,URG URG -j DROP
    ip6tables -A PORTSCAN -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
    ip6tables -A PORTSCAN -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    ip6tables -A PORTSCAN -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    ip6tables -A PORTSCAN -p tcp --tcp-flags ALL ALL -j DROP
    ip6tables -A PORTSCAN -p tcp --tcp-flags ALL NONE -j DROP
    ip6tables -A PORTSCAN -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
    ip6tables -A PORTSCAN -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
    ip6tables -A PORTSCAN -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

    # Protect from ping of death
    iptables -N PING_OF_DEATH
    iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request -m hashlimit --hashlimit 1/s --hashlimit-burst 10 --hashlimit-htable-expire 300000 --hashlimit-mode srcip --hashlimit-name t_PING_OF_DEATH -j RETURN
    iptables -A PING_OF_DEATH -j DROP
    iptables -A INPUT -p icmp --icmp-type echo-request -j PING_OF_DEATH

    ip6tables -N PING_OF_DEATH
    ip6tables -A PING_OF_DEATH -p icmpv6 --icmpv6-type echo-request -m hashlimit --hashlimit 1/s --hashlimit-burst 10 --hashlimit-htable-expire 300000 --hashlimit-mode srcip --hashlimit-name t_PING_OF_DEATH -j RETURN
    ip6tables -A PING_OF_DEATH -j DROP
    ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j PING_OF_DEATH

    # Protect from 80/443 DDoS attacks
    iptables -A INPUT -p tcp --syn -m multiport --dports 80,443 -m connlimit --connlimit-above 20 -j REJECT --reject-with tcp-reset
    ip6tables -A INPUT -p tcp --syn -m multiport --dports 80,443 -m connlimit --connlimit-above 20 -j REJECT --reject-with tcp-reset

    # Drop fragmented packages
    iptables -A INPUT -f -j DROP
    ip6tables -A INPUT -m frag -j DROP

    # SYN packets check
    iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
    ip6tables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

    # TCP Syn Flood
    iptables -A INPUT -p tcp --syn -m limit --limit 3/s -j ACCEPT
    ip6tables -A INPUT -p tcp --syn -m limit --limit 3/s -j ACCEPT

    # UDP Syn Flood
    iptables -A INPUT -p udp -m limit --limit 10/s -j ACCEPT
    ip6tables -A INPUT -p udp -m limit --limit 10/s -j ACCEPT
}

persist() {

    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
}

flush() {

    iptables -F
    iptables -X
    iptables -F -t mangle
    iptables -F -t nat

    ip6tables -F
    ip6tables -X
    ip6tables -F -t mangle
    ip6tables -F -t nat

    iptables -F INPUT
    iptables -F FORWARD
    iptables -F OUTPUT

    ip6tables -F INPUT
    ip6tables -F FORWARD
    ip6tables -F OUTPUT
}

stop() {

    flush

    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    ip6tables -P INPUT ACCEPT
    ip6tables -P FORWARD ACCEPT
    ip6tables -P OUTPUT ACCEPT

    persist
}

start() {

    flush

    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP

    ip6tables -P INPUT DROP
    ip6tables -P OUTPUT DROP
    ip6tables -P FORWARD DROP

    configure_network
    configure_hardening
    configure_input_chain
    configure_forward_chain
    configure_output_chain
    configure_postrouting

    persist
}

init

case "$1" in
    start)
        echo "gatekeeper [start]";
        start
    ;;
    stop)
        echo "gatekeeper [stop]";
        stop
    ;;
    restart)
        echo "gatekeeper [restart]";
        stop; start
    ;;
    *)
        echo "usage: $ sudo gatekeeper start|stop|restart"
esac

exit 0;
