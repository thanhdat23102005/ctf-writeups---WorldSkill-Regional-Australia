#!/bin/bash
# Helper: proxy an OpenSearch API call through Dashboards console
B="https://soc.challenges.root-me.pro"
M="${2:-GET}"
curl -s -b cookies.txt -c cookies.txt -m 60 -X POST \
  "$B/api/console/proxy?path=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1")&method=$M" \
  -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
  --data-binary "${3:-}"
