#!/bin/bash

# pdcfw - manages PDC Linux Netfilter/IPtables firewall configuration

# functions.sh - pdcfw functions
# Author: Ilari Korhonen, KTH Royal Institute of Technology
#
# Copyright (C) 2018 KTH Royal Institute of Technology. All rights reserved.
# See LICENSE file for more information.

# set defaults for executables
fwcmd="/usr/sbin/iptables"
save="/usr/sbin/iptables-save"
restore="/usr/sbin/iptables-restore"

mainfunc="$(dirname $0)/pdcfw-main.sh"
prog="$(basename $0)"

# default ruleset configuration file
IPTABLES_RULES="/etc/sysconfig/iptables"

# pdcfw defaults
TRUSTED_IFACES="lo" # trusted interfaces (everything allowed)
LIMIT_ICMP_ECHO="3/s" # limit for ICMP Echo Requests

LOG_LIMIT="3/s"
LOG_LIMIT_BURST="10"

# show_action - show command
function show_action()
{
    case "$1" in 
	running)
	    shift

	    fw=$(basename $fwcmd)

	    ${fwcmd} -S | while read line; do
		printf "${fw} ${line}\n"
	    done
	    ;;

	status)
	    shift
	    ${fwcmd} -L -v -n -t filter
	    ;;

	*)
	    echo "${prog}: usage ${prog} show [running|status|...]"
	    exit -1
	    ;;
    esac
}


# save_and_flush - saves current in-memory firewall rules to disk and resets 

function save_and_flush()
{
    # save existing in-memory ruleset to disk
    ${save} -t filter > ${IPTABLES_RULES}

    # flush in-memory ruleset
    ${fwcmd} --flush
}


# allow_trusted_if - accept all packets from/to trusted network interfaces

function allow_trusted_if()
{
    if [ $# -eq 1 ]; then	
	local chain=$1
	
	for iface in ${TRUSTED_IFACES}; do
	    ${fwcmd} -A ${chain} -i ${iface} -j ACCEPT
	done
    fi
}


# allow_established - accept all packets related to established connections

function allow_established()
{
    if [ $# -eq 1 ]; then
	local chain=$1

	${fwcmd} -A ${chain} -m state --state RELATED,ESTABLISHED -j ACCEPT
    fi
}


# allow_icmp_with_limits - accept ICMP packets, but only up to a limit

function allow_icmp_with_limits()
{
    if [ $# -eq 1 ]; then
	local chain=$1

	# for ICMP Echo Requests, we limit the number of packets
	${fwcmd} -A ${chain} -p icmp --icmp-type echo-request -m limit --limit ${LIMIT_ICMP_ECHO} -j ACCEPT
	${fwcmd} -A ${chain} -p icmp --icmp-type echo-request -j LOG --log-prefix "PDC FW: Excessive ICMP Echo:"
	${fwcmd} -A ${chain} -p icmp --icmp-type echo-request -j DROP

	# the rest of ICMP we allow blindly, for now
	${fwcmd} -A ${chain} -p icmp -j ACCEPT
    fi
}


# allow - generic macro for allowing packets

function allow()
{
    local chain=""
    local proto=""
    local iface=""
    local src=""
    local sport=""
    local dst=""
    local dport=""
    local state=""
    
    while [ $# -gt 0 ]; do
	case "$1" in
	    with)
		shift
		chain=$1
		shift
		;;
	    via)
		shift
		if [ "$1" != "any" ]; then
		    iface="-i $1"
		fi
		shift
		;;
	    proto)
		shift
		if [ "$1" != "any" ]; then
		    proto="-p $1"
		fi
		shift
		;;
	    from)
		shift
		if [ "$1" != "any" ]; then
		    src="-s $1"
		fi
		shift
		;;
	    sport)
		shift
		if [ "$1" != "any" ]; then
		    sport="--sport $1"
		fi
		shift
		;;
	    to)
		shift
		if [ "$1" != "any" ]; then
		    dst="-d $1"
		fi
		shift
		;;
	    dport)
		shift
		if [ "$1" != "any" ]; then
		    dport="--dport $1"
		fi
		shift
		;;
	    stateful)
		shift
		state="-m state --state NEW"
		;;
	    *)
		break
		;;
	esac
    done
    
    ${fwcmd} -A ${chain} ${iface} ${proto} ${src} ${sport} ${dst} ${dport} ${state} $@ -j ACCEPT
}


# drop_and_log_all - logs and drops all packets

function drop_and_log_all()
{
    if [ $# -eq 1 ]; then
	local chain=$1

	${fwcmd} -A ${chain} -j LOG -m limit --limit ${LOG_LIMIT} --limit-burst ${LOG_LIMIT_BURST} --log-prefix "PDC FW DROP (${chain}):"
	${fwcmd} -A ${chain} -j DROP
    fi
}


# reject_and_log_all - rejects (with ICMP) and logs dropped packets

function reject_and_log_all()
{
    if [ $# -eq 1 ]; then
	local chain=$1
	
	${fwcmd} -A ${chain} -j LOG --log-prefix "PDC FW REJECT (${chain}):"
	${fwcmd} -A ${chain} -j REJECT --reject-with icmp-host-prohibited
    fi
}


# set_default_policy - sets netfilter default policy

function set_default_policy()
{
    if [ $# -eq 2 ]; then
	local chain=$1
	local policy=$2

	# TODO: log policy reset
	${fwcmd} -P ${chain} ${policy}
    fi
}
