#!/bin/bash
cd "$(dirname "$0")"
echo "Leave this window open. Closing it stops the website."
echo "If the browser does not open, go to http://127.0.0.1:8808"
echo
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 was not found."
  echo "Install it from https://www.python.org/downloads/macos/"
  echo
  read -r -p "Press Return to close."
  exit 1
fi
python3 server.py --open
echo
echo "The website has stopped."
read -r -p "Press Return to close."
