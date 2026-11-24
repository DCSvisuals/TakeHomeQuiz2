# CST8808 Quiz 2: iptables log parser

The program reads an iptables kernel log, parses every line, and fills the quiz table. Events are grouped by source IP. The label for each group comes from the destination ports and the gaps between timestamps.

The website and the terminal script use the same parser. The page stays on this computer. Microsoft Edge, Google Chrome, Safari, and Firefox can open it.

No extra packages are required. The programs use the Python 3 standard library.

## Files

Keep these files in the same folder.

| File | Purpose |
|---|---|
| start.bat | Windows. Double-click to open the website. |
| report.bat | Windows. Double-click to print the report in a window. |
| start.command | Mac shortcut. Double-click to open the website. If the Mac blocks it, use the Terminal steps below. |
| server.py | The website. |
| index.html | The page the website shows. |
| parse_iptables.py | The parser. The website uses this file. |
| iptables.log | The quiz sample. |
| README.md | These instructions. |

Python may create a folder named `__pycache__` after a run. That folder is not part of the submission.

The folder can sit anywhere on the computer. The files above must stay together.

The website address is:

http://127.0.0.1:8808

## What the sample should show

The file has 43 lines. Line 40 says `Use code with caution.` and is not a log line, so the parser skips it. 42 events remain.

| Attacker IP | Target ports | Action | Diagnosis |
|---|---|---|---|
| 192.168.1.150 | 21, 22, 23, 25, 80, 443, 8080 | DROP | Vertical TCP SYN port scan |
| 203.0.113.42 | 22 (SSH) | ACCEPT | SSH brute force attempt |
| 198.51.100.77 | 80 (HTTP) | ALLOW | Low-and-slow HTTP attack |
| 198.51.100.99 | 80 (HTTP) | ALLOW | HTTP connection flood |

The 203.0.113.42 row is the example from the quiz handout. The script counts 10 connections to port 22, spaced 1-2 seconds apart.

## Run the website on Windows

1. If Python 3 is not installed, download it from https://www.python.org/downloads/windows/ . On the first screen of the installer, check **Add python.exe to PATH**, then finish the install.
2. Open the quiz folder.
3. Double-click **start.bat**.
4. The report opens in the browser.

Leave the black window open while you use the page. Close that window when you are finished. Closing it stops the website.

If the browser does not open by itself, open Microsoft Edge and go to http://127.0.0.1:8808

If start.bat says Python was not found, install Python as described in step 1, then double-click start.bat again.

To print the same report in a window, double-click **report.bat**. That window shows the four profiles, the indicators, and one line for every parsed event. Press a key to close it when you are done reading.

## Run the website on macOS

`start.bat` does not start the website on a Mac. Use Terminal.

1. If Python 3 is not installed, download it from https://www.python.org/downloads/macos/ and finish the install.
2. Open the Terminal app.
3. Type `cd` and then a space. Do not press Return yet.
4. Drag the quiz folder onto the Terminal window. The folder path appears after `cd`.
5. Press Return.
6. Type this command and press Return:

    python3 server.py

7. Leave the Terminal window open. When it prints the address, open Safari and go to http://127.0.0.1:8808
8. To stop the website, click the Terminal window and press Control-C.

If Terminal says that python3 was not found, install Python as described in step 1, then repeat from step 2.

You can also double-click **start.command**. If macOS says it cannot be opened, use the Terminal steps above. Control-click the file and choose Open if macOS asks for confirmation.

To print the report in Terminal, use the same `cd` steps, then type this command and press Return:

    python3 parse_iptables.py iptables.log

## What to show in person

1. Start the website and show the attack profile table. It has one row for each source address.
2. Point at one row in the normalized log and name the fields: time, rule prefix, SRC, and DPT.
3. Scroll to Indicators of compromise and read the four source addresses.

The page explains the limit of this log. An iptables line shows the connection attempt and the firewall decision. Usernames, passwords, URLs, and exploit strings are not in the file. The SSH authentication log and the web access log are the next evidence.

## Open a different log

On the website, click **Upload a log** and choose one or more `.log` or `.txt` files. You can also drop files onto the page. Every log you add stays in the **Log** list until you close the page. Choose a name in that list to view it. `iptables.log` is already in the list. Any other `.log` or `.txt` file in this folder is listed too.

In Terminal, pass the file name:

    python3 parse_iptables.py some-other.log
