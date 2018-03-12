#!/bin/bash

# include global definitions
source ${CONFIGDIR}/defs

# include local rules for INPUT,OUTPUT,FORWARD chains
source ${CONFIGDIR}/local-input.sh
source ${CONFIGDIR}/local-output.sh
source ${CONFIGDIR}/local-forward.sh

function main()
{
    # table: filter (packet filtering, default)
    # rule chains: INPUT, OUTPUT, FORWARD

    # rule chain: INPUT
    # description: incoming, packets destined to this host
    # default policy: ACCEPT
    set_default_policy INPUT ACCEPT

    # allow all from trusted interfaces, established connections, icmp w/ limits
    allow_trusted_interfaces INPUT
    allow_established INPUT
    allow_icmp_with_limits INPUT

    # execute local rules for INPUT
    local_input

    # allow SSH connections
    allow with INPUT proto tcp from any to $(hostname) dport 22 stateful

    # allow AFS cache manager callback
    allow with INPUT proto udp from any to $(hostname) dport 7001

    # drop the rest
    drop_and_log_all INPUT

    # rule chain: OUTPUT
    # description: outgoing, packets generated on this host
    # default policy: ACCEPT
    set_default_policy OUTPUT ACCEPT

    # execute local rules for OUTPUT
    local_output

    # rule chain: FORWARD
    # description: routing, packets destined to be routed
    # default policy: ACCEPT
    set_default_policy FORWARD ACCEPT

    # execute local rules for FORWARD
    local_forward

    # we drop and log all packets (by default, no routing)
    drop_and_log_all FORWARD
}
