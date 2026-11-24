#!/bin/bash
# start.sh - Launch Pramaan Forensic Platform
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "========================================================"
echo " Starting PRAMAAN (प्रमाण) Forensic Evidence Prototype "
echo " Compliant with BNSS §176(3) & BSA §63                  "
echo "========================================================"
echo ""
echo "Access the application at: http://localhost:3000"
echo "Press Ctrl+C to terminate the server."
echo ""

node server.js
