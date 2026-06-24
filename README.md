# Domain & DNS Reconnaissance Tool

A Python-based OSINT tool that investigates a domain's ownership history
and DNS configuration to flag patterns commonly associated with phishing
or scam websites.

## Why I Built This

After building a Phishing URL Detector that flags suspicious patterns in
a URL string itself, I wanted to go one layer deeper: investigate the
domain behind the URL. A newly-registered domain with hidden ownership
and no mail servers is a much stronger phishing signal than the URL text
alone — this tool automates that investigation.

## What It Does

1. **WHOIS Lookup** — retrieves registrar, creation date, and organization
   info for a domain.
2. **DNS Record Lookup** — fetches A (IP address), MX (mail server), and
   NS (name server) records.
3. **Risk Analysis** — flags red flags such as:
   - Domain registered in the last 30 days
   - Missing or hidden organization info (privacy-shielded registration)
   - No mail servers configured (unusual for a legitimate business)
   - Domain that doesn't resolve at all (NXDOMAIN)

## How It Works

The tool uses the `python-whois` library to query domain registries and
`dnspython` to perform DNS lookups. It compares the results against a
set of known phishing/scam indicators and prints a clear report with
any flags raised.

## Usage

```bash
pip install python-whois dnspython
python dns_recon.py
