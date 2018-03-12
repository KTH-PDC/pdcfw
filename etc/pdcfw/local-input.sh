#!/bin/bash

function local_input()
{
    # we allow all from/to the local GPFS InfiniBand network
    allow with INPUT via ib0 from any to any
}
