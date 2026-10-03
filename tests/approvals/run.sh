#!/bin/sh
# start proxy on :5547, API :18099
cd "$(dirname "$0")"
[ -f proxy.pid ] && kill $(cat proxy.pid) 2>/dev/null; sleep 0.5
mkdir -p home
HOME=$PWD/home FAULTWALL_TELEMETRY=false FAULTWALL_CONFIG_FILE=${CPCFG:-/nonexistent} FW_BYPASS_DETECTION=false PORT=18099 BIND_ADDR=127.0.0.1 \
FW_HOLD_TIMEOUT=${T:-} PGUSER=ec2-user ${FW_BIN:-/tmp/fw-appr-bin/faultwall} --proxy --listen 127.0.0.1:5547 --upstream 127.0.0.1:5544 --policies ${POL:-policies.yaml} > proxy.log 2>&1 < /dev/null &
echo $! > proxy.pid
sleep 1.5
