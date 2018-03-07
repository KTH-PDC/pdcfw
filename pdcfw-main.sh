#!/bin/bash

function main()
{
    # first we save in-memory rules to disk and flush all rules
    save_and_flush

    # table: filter (packet filtering, default)
    # rule chains: INPUT, OUTPUT, FORWARD
    
    # rule chain: INPUT
    # description: incoming, packets destined to this host
    
    # default policy: ACCEPT
    set_default_policy INPUT ACCEPT
    
    # allow all from trusted interfaces, established connections, icmp w/ limits
    allow_trusted_if INPUT
    allow_established INPUT
    allow_icmp_with_limits INPUT

    # allow SSH connections
    allow with INPUT proto tcp from any to $(hostname),localhost dport 22 stateful

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
}
