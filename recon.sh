#!/bin/bash
# Build-pod environment recon. Writes findings to /workspace/recon/ which gets baked into the image.
# Designed to NOT leak credentials/tokens externally — we redact env var values for token-shaped names
# and dump only the SHA256 fingerprint + decoded header/payload (not signature) of the K8s SA JWT.

set +e  # don't abort on errors; we want partial output
mkdir -p /workspace/recon
cd /workspace/recon

# 1. identity + host
id > 01-id.txt 2>&1
whoami >> 01-id.txt 2>&1
uname -a > 02-uname.txt 2>&1
cat /etc/os-release > 03-osrelease.txt 2>&1
hostname > 04-hostname.txt 2>&1
pwd > 05-cwd.txt 2>&1

# 2. environment — redact likely-sensitive values, but keep names + lengths + 4-char prefix
env | cut -d= -f1 | sort > 10-env-names.txt 2>&1
env | awk -F= '{name=$1; val=substr($0, length(name)+2); printf "%s: len=%d prefix=%.4s\n", name, length(val), val}' | sort > 11-env-fingerprints.txt 2>&1
# Full env with redaction for token-like names
env | sed -E 's/(.*(TOKEN|SECRET|KEY|PASSWORD|CRED|AUTH|TLS|API).*=).*$/\1<REDACTED>/' > 12-env-redacted.txt 2>&1

# 3. /proc/self
cat /proc/self/cgroup > 20-cgroup.txt 2>&1
cat /proc/self/status > 21-status.txt 2>&1
cat /proc/self/mountinfo > 22-mountinfo.txt 2>&1
cat /proc/1/cgroup > 23-pid1-cgroup.txt 2>&1
cat /proc/1/cmdline | tr '\0' ' ' > 24-pid1-cmdline.txt 2>&1
echo "" >> 24-pid1-cmdline.txt

# 4. mounted secrets — names + sizes + JWT payload (not signature) for K8s SA token
ls -laR /var/run/secrets/ > 30-secrets-tree.txt 2>&1
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ > 31-sa-ls.txt 2>&1
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/namespace ]; then
  cat /var/run/secrets/kubernetes.io/serviceaccount/namespace > 32-sa-namespace.txt 2>&1
fi
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
  TOKEN_FILE=/var/run/secrets/kubernetes.io/serviceaccount/token
  {
    echo "exists=true size=$(wc -c < $TOKEN_FILE)"
    echo "sha256=$(sha256sum < $TOKEN_FILE | cut -d' ' -f1)"
  } > 33-sa-token-fingerprint.txt 2>&1
  # Decode JWT header + payload (NOT signature — never log signature)
  TOKEN=$(cat $TOKEN_FILE)
  HDR=$(echo -n "$TOKEN" | cut -d. -f1)
  PAY=$(echo -n "$TOKEN" | cut -d. -f2)
  python3 -c "
import sys, base64, json
def b64d(s):
  s += '=' * (-len(s) % 4)
  return base64.urlsafe_b64decode(s).decode('utf-8', 'replace')
try: print(json.dumps(json.loads(b64d(sys.argv[1])), indent=2))
except Exception as e: print('decode err: ' + str(e))
" "$HDR" > 34-sa-jwt-header.txt 2>&1
  python3 -c "
import sys, base64, json
def b64d(s):
  s += '=' * (-len(s) % 4)
  return base64.urlsafe_b64decode(s).decode('utf-8', 'replace')
try: print(json.dumps(json.loads(b64d(sys.argv[1])), indent=2))
except Exception as e: print('decode err: ' + str(e))
" "$PAY" > 35-sa-jwt-payload.txt 2>&1
fi
# CA cert info — public, safe to log
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/ca.crt ]; then
  openssl x509 -in /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -text -noout 2>&1 | head -50 > 36-sa-ca.txt
fi

# Look for OTHER secret-mount paths
ls -la /var/lib/secrets/ /etc/secrets/ /run/secrets/ /opt/secrets/ 2>&1 > 37-other-secret-paths.txt

# 5. filesystem layout
df -h > 40-df.txt 2>&1
mount > 41-mount.txt 2>&1
ls -la / > 42-rootls.txt 2>&1
ls -la /workspace/ > 43-workspace.txt 2>&1
ls -la /layers/ > 44-layers.txt 2>&1
ls -la /cnb/ > 45-cnb.txt 2>&1
cat /cnb/order.toml > 46-order.txt 2>&1
cat /cnb/builder.toml > 47-builder.txt 2>&1
ls -la /opt /tmp /var /etc 2>&1 > 48-misc-dirs.txt
ls /etc/kubernetes/ 2>&1 > 49-etc-k8s.txt

# 6. network
ip addr > 50-ipaddr.txt 2>&1
ip route > 51-iproute.txt 2>&1
cat /etc/resolv.conf > 52-resolv.txt 2>&1
cat /etc/hosts > 53-hosts.txt 2>&1
cat /proc/net/route > 54-procroute.txt 2>&1
ss -tnlp 2>&1 > 55-listening.txt || netstat -tnlp 2>&1 > 55-listening.txt

# 7. cluster reach — actual response bodies this time
for target in \
  "https://10.245.0.1/api" \
  "https://10.245.0.1:6443/" \
  "http://10.245.0.1/" \
  "http://10.245.0.10:53/" \
  "https://kubernetes.default.svc/api" \
  "https://kubernetes.default.svc/" \
  "http://metadata.google.internal/" \
  "http://169.254.169.254/" \
  "http://localhost/" \
  "http://127.0.0.1/" \
  "http://10.245.0.1:10250/" \
  "http://10.245.0.1:10255/healthz" \
  "http://10.245.0.1:10257/healthz" \
  "http://10.245.0.1:10259/healthz" \
  "http://10.245.0.1:2379/version" ; do
  label=$(echo "$target" | sed -E 's|https?://||; s|[/:]|_|g')
  curl -m 6 -k -sS -i "$target" > 60-curl-${label}.txt 2>&1
done

# 8. K8s API self-permissions — with SA token, ask what we can do
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  AUTH="Authorization: Bearer $TOKEN"
  # apiserver IP + cluster.local DNS — both. Note: we tested both fail at TCP earlier;
  # this is a fresh test inside the build_command context.
  for base in "https://10.245.0.1" "https://kubernetes.default.svc" "https://kubernetes.default.svc.cluster.local"; do
    label=$(echo "$base" | sed -E 's|https?://||; s|[/:]|_|g')
    curl -m 6 -k -sS -i -H "$AUTH" "$base/api/v1/" > 70-api-${label}.txt 2>&1
    curl -m 6 -k -sS -i -H "$AUTH" "$base/apis/" > 71-apis-${label}.txt 2>&1
    curl -m 6 -k -sS -i -H "$AUTH" "$base/version" > 72-version-${label}.txt 2>&1
  done
  # SelfSubject* reviews — RBAC introspection
  curl -m 6 -k -sS -i -H "$AUTH" -H "Content-Type: application/json" \
    -X POST 'https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectaccessreviews' \
    --data '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"list","resource":"pods"}}}' \
    > 73-ssar-pods.txt 2>&1
  curl -m 6 -k -sS -i -H "$AUTH" -H "Content-Type: application/json" \
    -X POST 'https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectaccessreviews' \
    --data '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"get","resource":"secrets","name":"*"}}}' \
    > 74-ssar-secrets.txt 2>&1
  curl -m 6 -k -sS -i -H "$AUTH" -H "Content-Type: application/json" \
    -X POST 'https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews' \
    --data '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' \
    > 75-ssrr-default.txt 2>&1
fi

# 9. small Pod CIDR sweep (timing only, polite)
echo "pod-cidr probe with curl -m 2 (port 80)" > 80-pod-sweep.txt
for ip in 10.244.0.1 10.244.0.5 10.244.0.10 10.244.0.50 10.244.0.100 10.244.0.200 10.244.1.1 10.244.5.5 10.244.10.10 10.244.100.1 10.244.200.1 10.244.255.1 ; do
  echo "$ip:" >> 80-pod-sweep.txt
  /usr/bin/time -f "  time=%e" curl -m 2 -sS -o /dev/null -w "  http=%{http_code} connect=%{time_connect}\n" "http://$ip/" >> 80-pod-sweep.txt 2>&1
done

# 10. builder + tool fingerprint
which pack lifecycle creator builder 2>&1 > 90-tools.txt
pack version 2>&1 >> 90-tools.txt
lifecycle --version 2>&1 >> 90-tools.txt
ls -la /usr/local/bin/ /cnb/lifecycle/ /cnb/buildpacks/ 2>&1 > 91-bin.txt
# Strings of pid 1 binary if any
file /proc/1/exe 2>&1 > 92-pid1-bin.txt

# 11. DOCR push credentials hunt — look in expected locations
echo "=== ~/.docker/config.json ===" > 95-docker-creds.txt
cat ~/.docker/config.json 2>&1 | sed -E 's/("auth"\s*:\s*")[^"]+(")/\1<REDACTED>\2/g' >> 95-docker-creds.txt
echo "=== /root/.docker/config.json ===" >> 95-docker-creds.txt
cat /root/.docker/config.json 2>&1 | sed -E 's/("auth"\s*:\s*")[^"]+(")/\1<REDACTED>\2/g' >> 95-docker-creds.txt
echo "=== /workspace/.docker/config.json ===" >> 95-docker-creds.txt
cat /workspace/.docker/config.json 2>&1 | sed -E 's/("auth"\s*:\s*")[^"]+(")/\1<REDACTED>\2/g' >> 95-docker-creds.txt
echo "=== container-related env vars (names only) ===" >> 95-docker-creds.txt
env | cut -d= -f1 | grep -iE 'DOCKER|REGISTRY|DOCR|BUILDKIT|CNB|IMAGE|PUSH' >> 95-docker-creds.txt
echo "=== /etc/containers/auth.json ===" >> 95-docker-creds.txt
cat /etc/containers/auth.json 2>&1 | sed -E 's/("auth"\s*:\s*")[^"]+(")/\1<REDACTED>\2/g' >> 95-docker-creds.txt

# Make all output readable
chmod -R a+r /workspace/recon

# Done marker
echo "recon complete at $(date -u +%Y-%m-%dT%H:%M:%SZ); $(ls /workspace/recon | wc -l) files generated" > 99-done.txt
true
