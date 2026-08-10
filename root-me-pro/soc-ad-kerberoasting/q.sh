#!/bin/bash
# q.sh - POST a search body to the OpenSearch index via the Dashboards console proxy
B="https://soc.challenges.root-me.pro"
IDX="index-be447e0099b7-winlogbeat"
curl -sS -m 90 -b ~/ctf/rootme-pro/soc-ad-kerberoasting/cookies.txt \
  -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  -X POST "$B/api/console/proxy?path=$IDX/_search&method=POST" -d @-
