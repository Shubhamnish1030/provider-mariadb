#!/bin/sh
# Usage: connect.sh <instance> verify|plain
#
# verify: connects with the ca.crt of the instance's connection Secret,
#         verifies the server certificate and requires a TLS cipher.
# plain:  connects without TLS and must be refused (requireTLS).
set -eu
instance=$1
mode=$2
secret="$instance-conn"
pod="tls-check-$instance-$mode"

case "$mode" in
  verify) args='set -eu; cipher=$(mariadb -h \"$DB_HOST\" -P \"$DB_PORT\" -u \"$DB_USER\" --ssl-ca=/tls/ca.crt --ssl-verify-server-cert -Nse \"SHOW STATUS LIKE '"'"'Ssl_cipher'"'"';\" | awk '"'"'{print $2}'"'"'); test -n \"$cipher\"; echo \"TLS cipher: $cipher\"' ;;
  plain) args='set -u; if mariadb -h \"$DB_HOST\" -P \"$DB_PORT\" -u \"$DB_USER\" --skip-ssl -Nse \"SELECT 1;\"; then echo \"FAIL: connected without TLS\"; exit 1; fi; echo \"refused without TLS\"' ;;
  *) echo "unknown mode $mode" >&2; exit 2 ;;
esac

kubectl -n "$NAMESPACE" delete pod "$pod" --ignore-not-found --wait=true >/dev/null
kubectl -n "$NAMESPACE" run "$pod" \
  --rm -i --restart=Never \
  --image=mariadb:12.3 \
  --overrides="{
    \"spec\": {
      \"containers\": [{
        \"name\": \"check\",
        \"image\": \"mariadb:12.3\",
        \"command\": [\"sh\", \"-c\"],
        \"args\": [\"$args\"],
        \"env\": [
          {\"name\": \"DB_HOST\", \"valueFrom\": {\"secretKeyRef\": {\"name\": \"$secret\", \"key\": \"host\"}}},
          {\"name\": \"DB_PORT\", \"valueFrom\": {\"secretKeyRef\": {\"name\": \"$secret\", \"key\": \"port\"}}},
          {\"name\": \"DB_USER\", \"valueFrom\": {\"secretKeyRef\": {\"name\": \"$secret\", \"key\": \"username\"}}},
          {\"name\": \"MYSQL_PWD\", \"valueFrom\": {\"secretKeyRef\": {\"name\": \"$secret\", \"key\": \"password\"}}}
        ],
        \"volumeMounts\": [{\"name\": \"tls\", \"mountPath\": \"/tls\", \"readOnly\": true}]
      }],
      \"volumes\": [{\"name\": \"tls\", \"secret\": {\"secretName\": \"$secret\", \"items\": [{\"key\": \"ca.crt\", \"path\": \"ca.crt\"}]}}]
    }
  }"
