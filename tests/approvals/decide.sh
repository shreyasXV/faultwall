#!/bin/sh
# decide.sh approve|deny [delay]  -> waits for first hold, decides it
sleep ${2:-1}
for i in 1 2 3 4 5 6 7 8 9 10; do
  id=$(curl -s 127.0.0.1:18099/api/holds | /opt/homebrew/bin/python3.13 -c 'import sys,json; h=json.load(sys.stdin)["holds"]; print(h[0]["id"] if h else "")')
  [ -n "$id" ] && break; sleep 0.3
done
curl -s -XPOST 127.0.0.1:18099/api/holds/$id/$1 -d '{"by":"e2e-tester","reason":"'"${3:-}"'"}'
