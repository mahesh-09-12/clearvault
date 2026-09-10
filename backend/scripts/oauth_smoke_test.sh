#!/usr/bin/env bash
set -euo pipefail

# Usage: BACKEND_URL=... GOOGLE_CLIENT_ID=... GOOGLE_CALLBACK_URL=... FRONTEND_URL=... ./oauth_smoke_test.sh

BACKEND_URL=${BACKEND_URL:-http://localhost:4000}
GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID:-}
GOOGLE_CALLBACK_URL=${GOOGLE_CALLBACK_URL:-}
FRONTEND_URL=${FRONTEND_URL:-http://localhost:5173}

if [ -z "$GOOGLE_CLIENT_ID" ] || [ -z "$GOOGLE_CALLBACK_URL" ]; then
  echo "ERROR: Please set GOOGLE_CLIENT_ID and GOOGLE_CALLBACK_URL environment variables." >&2
  exit 2
fi

echo "Using BACKEND_URL=$BACKEND_URL"

echo "\n1) Requesting /api/auth/google and checking redirect to Google..."
headers=$(curl -s -D - -o /dev/null "$BACKEND_URL/api/auth/google")
status=$(echo "$headers" | head -n1 | awk '{print $2}')
location=$(echo "$headers" | grep -i '^Location:' | sed -E 's/Location: //I' | tr -d '\r\n')
setcookie=$(echo "$headers" | grep -i '^Set-Cookie:' | tr -d '\r\n')

if [ "$status" != "302" ]; then
  echo "FAIL: expected 302 from /api/auth/google, got $status" >&2
  exit 3
fi

if [[ "$location" != https://accounts.google.com/* ]]; then
  echo "FAIL: expected Location to start with https://accounts.google.com, got: $location" >&2
  exit 4
fi

# URL-encode callback for comparison
encoded_callback=$(python -c "import urllib.parse,os; print(urllib.parse.quote(os.environ['GOOGLE_CALLBACK_URL'], safe=''))" )

if ! echo "$location" | grep -q "client_id=$GOOGLE_CLIENT_ID"; then
  echo "FAIL: client_id not present or doesn't match in Google redirect: $location" >&2
  exit 5
fi

if ! echo "$location" | grep -q "redirect_uri=$encoded_callback"; then
  echo "FAIL: redirect_uri not present or does not match encoded GOOGLE_CALLBACK_URL in Google redirect: $location" >&2
  echo "encoded callback: $encoded_callback" >&2
  exit 6
fi

if ! echo "$setcookie" | grep -qi "cv_oauth_state="; then
  echo "FAIL: state cookie 'cv_oauth_state' not set in response" >&2
  exit 7
fi

echo "OK: auth start redirect looks correct."


echo "\n2) Calling callback without code should redirect to frontend login with oauth=invalid_response..."
headers_cb=$(curl -s -D - -o /dev/null "$BACKEND_URL/api/auth/google/callback")
status_cb=$(echo "$headers_cb" | head -n1 | awk '{print $2}')
location_cb=$(echo "$headers_cb" | grep -i '^Location:' | sed -E 's/Location: //I' | tr -d '\r\n')

if [ "$status_cb" != "302" ]; then
  echo "FAIL: expected 302 from callback without code, got $status_cb" >&2
  exit 8
fi

if ! echo "$location_cb" | grep -q "${FRONTEND_URL}/login"; then
  echo "FAIL: expected callback to redirect to frontend login, got: $location_cb" >&2
  exit 9
fi

if ! echo "$location_cb" | grep -q "oauth=invalid_response"; then
  echo "FAIL: expected oauth=invalid_response param in redirect, got: $location_cb" >&2
  exit 10
fi

echo "OK: callback without code behaves as expected."


echo "\n3) /api/auth/me must return 401 without session cookie..."
me_res=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/api/auth/me")
if [ "$me_res" != "401" ]; then
  echo "FAIL: expected 401 from /api/auth/me when unauthenticated, got $me_res" >&2
  exit 11
fi

echo "OK: /api/auth/me returns 401 unauthenticated."


echo "\nSMOKE TESTS PASSED"
exit 0
