#!/bin/bash

# pdcfw - manages PDC Linux Netfilter/IPtables firewall configuration

# functions.sh - pdcfw functions
# Author: Ilari Korhonen, KTH Royal Institute of Technology
#
# Copyright (C) 2018 KTH Royal Institute of Technology. All rights reserved.
# See LICENSE file for more information.

# set defaults for executables and paths
fwcmd="/usr/sbin/iptables"
save="/usr/sbin/iptables-save"
restore="/usr/sbin/iptables-restore"
configfile="/etc/sysconfig/pdcfw"
prog="$(basename $0)"

# pdcfw defaults
MAIN_FUNC="$(dirname $0)/pdcfw-main.sh"             # default main function
IPTABLES_RULES="/etc/sysconfig/iptables"            # default ruleset configuration file
TRUSTED_IFACES="lo"                                 # trusted interfaces (everything allowed)
LIMIT_ICMP_ECHO="3/s"                               # throttling limit for ICMP Echo Requests
LIMIT_ICMP_ECHO_BURST="10"                          # burst limit for ICMP Echo Requests
LIMIT_LOG="3/s"                                     # throttling limit for logging
LIMIT_LOG_BURST="10"                                # burst limit for logging


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


# save - saves current in-memory firewall rules to a file

function save()
{
    # save existing in-memory ruleset to disk
    ${save} -t filter > ${IPTABLES_RULES}
}


# flush - flushes current in-memory ruleset

function flush()
{
    # flush in-memory ruleset
    ${fwcmd} --flush
}


# add_filter_rule - add a rule to IPTables filter table
function add_filter_rule()
{
    local chain=""
    local proto=""
    local iface=""
    local src=""
    local sport=""
    local dst=""
    local dport=""
    local state=""
    local limit=""
    local limitburst=""
    local icmptype=""
    local logprefix=""
    local rejectwith=""
    local jump=""
    
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

	    state)
		shift
		state="-m state --state $1"
		shift
		;;
	    
	    limit)
		shift
		limit="-m limit --limit $1"
		shift
		;;

	    limit-burst)
		shift
		limitburst="--limit-burst $1"
		shift
		;;

	    icmp-type)
		shift
		icmptype="--icmp-type $1"
		shift
		;;

	    log-prefix)
		shift
		logprefix="--log-prefix $1"
		shift
		;;

	    reject-with)
		shift
		rejectwith="--reject-with $1"
		shift
		;;

	    jump)
		shift
		jump="-j $1"
		shift
		;;

	    # at first unknown argument, stop parsing
	    *)
		break
		;;
	esac
    done

    # execute iptables add with parsed arguments and the rest
    ${fwcmd} -A ${chain} \
	     ${iface} \
	     ${proto} \
	     ${icmptype} \
	     ${src} \
	     ${sport} \
	     ${dst} \
	     ${dport} \
	     ${state} \
	     ${limit} \
	     ${limitburst} \
	     ${rejectwith} \
	     ${jump} \
	     ${logprefix} \
	     $@
}


# allow - generic macro for a rule accepting packets

function allow()
{
    add_filter_rule $@ jump ACCEPT
}


# drop - generic macro for dropping packets

function drop()
{
    add_filter_rule $@ jump DROP
}


# reject - generic macro for rejecting packets

function reject()
{
    add_filter_rule $@ jump REJECT
}


# log - generic macro for logging packets

function log()
{
    add_filter_rule $@ jump LOG
}


# allow_trusted_interfaces - accept all packets from/to trusted network interfaces

function allow_trusted_interfaces()
{
    if [ $# -eq 1 ]; then	
	local chain=$1
	
	for iface in ${TRUSTED_IFACES}; do
	    allow with ${chain} via ${iface} from any to any
	done
    fi
}


# allow_established - accept all packets related to established connections

function allow_established()
{
    if [ $# -eq 1 ]; then
	local chain=$1

	allow with ${chain} state RELATED,ESTABLISHED
    fi
}


# allow_icmp_with_limits - accept ICMP packets, but only up to a limit

function allow_icmp_with_limits()
{
    if [ $# -eq 1 ]; then
	local chain=$1

	# for ICMP Echo Requests, we limit the number of packets
	allow with ${chain} proto icmp icmp-type echo-request limit ${LIMIT_ICMP_ECHO}
	log with ${chain} proto icmp icmp-type echo-request log-prefix "DROP:ICMP:"
	drop with ${chain} proto icmp icmp-type echo-request

	# the rest of ICMP we allow blindly, for now
	allow with ${chain} proto icmp	
    fi
}


# drop_and_log_all - logs and drops all packets

function drop_and_log_all()
{
    if [ $# -eq 1 ]; then
	local chain=$1

	log with ${chain} limit ${LIMIT_LOG} limit-burst ${LIMIT_LOG_BURST} log-prefix "DROP:${chain}:"
	drop with ${chain}	
    fi
}


# reject_and_log_all - rejects (with ICMP) and logs dropped packets

function reject_and_log_all()
{
    if [ $# -eq 1 ]; then
	local chain=$1

	log with ${chain} limit ${LIMIT_LOG} limit-burst ${LIMIT_LOG_BURST} log-prefix "REJECT:${chain}"
	reject with ${chain} reject-with icmp-host-prohibited
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
