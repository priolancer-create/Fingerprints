# CYBERX OSINT INTELLIGENCE V3.0

A Termux-friendly, public-source OSINT utility with a terminal menu and a mobile web dashboard.

## Features
- Email syntax and domain mail configuration (MX, SPF, DMARC)
- Domain DNS and RDAP lookup
- Username lookup through the documented public GitHub user API plus manual search links
- Phone number parsing/validation using libphonenumber metadata
- SQLite search history
- JSON and HTML reports
- Mobile-friendly Flask dashboard

## Install on Android Termux
```bash
pkg update -y && pkg upgrade -y
pkg install python -y
mkdir -p ~/cyberx-osint
# Copy cyberx_osint.py and requirements.txt into ~/cyberx-osint
cd ~/cyberx-osint
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run terminal menu
```bash
python cyberx_osint.py
```

## Run dashboard
```bash
python cyberx_osint.py --web
```
Open `http://127.0.0.1:5000` in the phone browser. Keep Termux running while using the dashboard.

## CLI examples
```bash
python cyberx_osint.py --type email --value you@example.com --report json
python cyberx_osint.py --type username --value octocat --report html
python cyberx_osint.py --type phone --value +8801712345678 --region BD
python cyberx_osint.py --type domain --value example.com --report html
```

## Test
```bash
python cyberx_osint.py --type email --value invalid-email
# Expected: clear validation error and non-zero exit

python cyberx_osint.py --type username --value octocat
# Expected: public GitHub profile metadata if the GitHub API is reachable

python cyberx_osint.py --type phone --value +8801712345678 --region BD
# Expected: parsed numbering-plan metadata; validity depends on the number

python cyberx_osint.py --web
# Open /health in browser: http://127.0.0.1:5000/health
```

## Important limitations
- Email checks do not verify mailbox existence or ownership.
- Username search is not a universal account-enumeration engine; GitHub is queried through its public API. Other search links are manual.
- Phone metadata does not identify a subscriber, track a phone, or reveal live location.
- RDAP/DNS/API results depend on internet access, upstream availability, and rate limits.
- The evidence score measures returned evidence/source coverage only. It is not an identity confidence probability.
- Use only for lawful, authorized research. Do not use results to harass, dox, stalk, or access accounts without permission.
