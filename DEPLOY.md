# Free deployment guide for DataVault AI

Free plans change often, so confirm current limits on each provider's pricing page before relying on them.
Never commit `.env`. Put keys in the host's secret/environment settings instead.

## Before you start: make your keys
Run locally: `python scripts/gen_keys.py`, then copy the single value after `DATAVAULT_KEYS=` in `.env`.
Format: `name:role:key,name:role:key` (each key at least 24 characters). Do not share it.

## Option A: Render (easiest, free web service, HTTPS included)
1. Push the project to a GitHub repo (without `.env`).
2. On render.com: New > Web Service > connect the repo > Runtime: Docker > Instance type: Free.
3. Add environment variable `DATAVAULT_KEYS` with the value from above.
4. Deploy. Open the https://....onrender.com address and paste a key.
Notes: free services sleep when idle (first request is slow), and the disk is not persistent, so the audit
history resets on restart. Fine for a demo, not for real records.

## Option B: IBM LinuxONE Community Cloud (for your LinuxONE claim)
1. Request a free trial virtual server on the IBM LinuxONE Community Cloud (IBM sets the trial length and approval).
2. SSH in, then: `unzip datavault-ai.zip && cd datavault-ai && python3 -m venv .venv && . .venv/bin/activate`
3. `pip install -r requirements-dev.txt && pytest` (record whether this passes on s390x: this is your "evaluated" evidence)
4. `python scripts/gen_keys.py`, then `./run.sh` (or the systemd service from the chat guide).
5. Keep it on 127.0.0.1 and put HTTPS in front (Caddy or nginx), or use an SSH tunnel: `ssh -L 8443:127.0.0.1:8443 user@SERVER`
   then open http://127.0.0.1:8443 on your own computer.

## Option C: Always-free cloud VM (e.g. Oracle Cloud Always Free)
Same steps as Option B on the VM. Open only ports 22 and 443, run the app on 127.0.0.1, add Caddy for HTTPS.

## After deploying: quick check
- Open /healthz: should show {"status":"ok"}.
- Submit the demo prompts from the chat (clean, masked, blocked).
- Confirm that a wrong or missing key gives an error.

## What to claim
Demonstrated = ran and tested. Evaluated = tested on LinuxONE. Proposed = everything else.
