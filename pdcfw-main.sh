#!/bin/bash

function main()
{
    # table: filter (packet filtering, default)
    # rule chains: INPUT, OUTPUT, FORWARD

    if [ ${commit} == "true" ]; then
	${fwcmd} "*filter"
    fi
    
    # rule chain: INPUT
    # description: incoming, packets destined to this host
    
    # default policy: ACCEPT
    set_default_policy INPUT ACCEPT
    
    # allow all from trusted interfaces, established connections, icmp w/ limits
    allow_trusted_interfaces INPUT
    allow_established INPUT
    allow_icmp_with_limits INPUT

    for myaddr in $(hostname) localhost; do
	# allow SSH connections
	allow with INPUT proto tcp from any to ${myaddr} dport 22 stateful

	# allow AFS cache manager callback in
	allow with INPUT proto udp from any to ${myaddr} dport 7001
    done

    # drop the rest
    drop_and_log_all INPUT


    # rule chain: OUTPUT
    # description: outgoing, packets generated on this host

    # default policy: ACCEPT
    set_default_policy OUTPUT ACCEPT


    # rule chain: FORWARD
    # description: routing, packets destined to be routed

    # default policy: ACCEPT
    set_default_policy FORWARD ACCEPT

    # we drop and log all packets (no routing!)
    drop_and_log_all FORWARD

    if [ ${commit} == "true" ]; then
	${fwcmd} "COMMIT"
    fi
}
