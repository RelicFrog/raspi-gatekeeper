# RelicFrog Raspy PI "Gatekeeper" Firewall

[![Software License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![System Version](https://img.shields.io/badge/Version-1.0.0-blue.svg)](VERSION)
[![Documentation](https://img.shields.io/badge/DOC-link-green.svg)](https://google.com)

_The current documentation in this repository is not yet final and will be adjusted and extended over the next commits according to the extended functionality of this Raspberry PI Firewall configuration script._

## Table of contents
* [General](#general)
* [Goals](#goals)
* [Technologies](#technologies)
* [Setup](#requirements--setup)
* [Commands](#commands) 
* [Contribution](#contribution)

## General

This repository is used to provide a working firewall configuration for public accessible Raspberry PI systems. This script can be used as service based controller for the corresponding iptables rule-sets. The DNS relevant rules have already been prepared for the use of the Q9 DNS service. This firewall pre-definition works also fine with your PI-Hole service stack.

### Goals

The purpose of this script is to provide a basic (service based) control of the most important iptables rule-sets for publicly accessible systems for raspberry pi devices.

- decoupled input, output and forwarding rule chains
- dedicated advanced hardening chain rule sets
- service oriented exec modes (start, stop, restart)
- persistence layer (using iptables-persistent)
- ipv4 and corresponding ipv6 rule definitions

## Technologies

* iptables: 1.8.2
* bash: 5.0.3

## Requirements + Setup

Please make sure that an executable iptables environment already exists on your raspberry pi and that you have installed appropriate tools to persist the rules.

* iptables > 1.6
* iptables-persistent > 1.0.n
* fail2ban (optional)

Clone this repository into your /opt directory, set exec bit and create a symbolic link to /usr/local/sbin

`cd /opt ; sudo git clone git@github.com:RelicFrog/raspi-gatekeeper.git && sudo chmod +x ./raspi-gatekeeper/gatekeeper.sh`
`sudo ln -sf /opt/raspi-gatekeeper/gatekeeper.sh /usr/local/sbin/gatekeeper`

## Commands

* start firewall: `sudo gatekeeper start`
* stop firewall: `sudo gatekeeper stop`
* restart firewall: `sudo gatekeeper restart`

## Rules

The current rules are primarily to be understood as basic sets of rules and can be adapted accordingly at any time. This configuration was developed during my PI-Hole project work and runs accordingly well in a Raspberry PI environment setup for PI-Hole.

### Input

| Port(s)          | Description |
|------------------|-------------|
| `22`             | allow SSH access to your system |
| `53/tcp`         | allow DNS by tcp access to your system |
| `53/udp`         | allow DNS by udp access to your system |
| `137,138,139`    | allow NetBIOS Name Service, Datagram Service, Session Service to your system |
| `953,5353,57621` | allow mDNS/DNS RNDC Service to your system |
| `80,443`         | allow webserver (http/https) access to your system |
| `67,68,69`       | allow DHCP service access to your system |
| `icmp/multicast` | allow local network ICMP service ping to your system |

### Output

| Port(s)          | Description |
|------------------|-------------|
| `22`             | allow SSH access from your system |
| `53/tcp`         | allow DNS by tcp access from your system |
| `53/udp`         | allow DNS by udp access from your system |
| `icmp/multicast` | allow local network ICMP service ping from your system |

### Forward

| Port(s)          | Description |
|------------------|-------------|
| `53/tcp`         | forward DNS by tcp access through your system |
| `53/udp`         | allow DNS by udp access through your system |
| `80,443`         | allow webserver (http/https) access through your system |
| `123`            | allow NTP access through your system |
| `587`            | allow submission access through your system |

## Contribution

Extensions and adaptations to this repository are always welcome and expressly requested!