!pip install python-whois
!pip install dnspython
import whois
import dns.resolver
from datetime import datetime, timezone

# Step 1: Ask the user for a domain
domain = input("Enter a domain to check (e.g. example.com): ").strip()
domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

print("\nLooking up:", domain)
print("-" * 50)

# Step 2: WHOIS lookup — find out who registered the domain and when
try:
    info = whois.whois(domain)
    creation_date = info.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]  # some registrars return a list

    print("Registrar:", info.registrar)
    print("Created on:", creation_date)
    print("Organization:", info.org)

    # How old is the domain, in days?
    if creation_date:
        # Make datetime.now() timezone-aware if creation_date is timezone-aware
        if creation_date.tzinfo is not None and creation_date.tzinfo.utcoffset(creation_date) is not None:
            now = datetime.now(timezone.utc).astimezone(creation_date.tzinfo)
        else:
            now = datetime.now()

        age_in_days = (now - creation_date).days
        print("Domain age:", age_in_days, "days")
    else:
        age_in_days = None

    whois_found = True

except Exception as e:
    print("WHOIS lookup failed:", e)
    whois_found = False
    age_in_days = None
    info = None

# Step 3: DNS lookup — find mail servers and IP address
print("\nDNS Records:")

try:
    mx_records = dns.resolver.resolve(domain, "MX")
    mx_list = [str(r) for r in mx_records]
except Exception:
    mx_list = []

try:
    a_records = dns.resolver.resolve(domain, "A")
    a_list = [str(r) for r in a_records]
except Exception:
    a_list = []

print("Mail servers (MX):", mx_list)
print("IP address (A):", a_list)

# Step 4: Check for red flags
print("\nRisk Flags:")
flags_found = False

if not whois_found:
    print("[FLAG] Could not find WHOIS info for this domain.")
    flags_found = True

if age_in_days is not None and age_in_days < 30:
    print(f"[FLAG] Domain is only {age_in_days} days old — common for phishing sites.")
    flags_found = True

if whois_found and info and not info.org:
    print("[FLAG] No organization listed — ownership may be hidden.")
    flags_found = True

if mx_list == []:
    print("[FLAG] No mail servers found — unusual for a real business.")
    flags_found = True

if a_list == []:
    print("[FLAG] Domain does not point to any website (no A record).")
    flags_found = True

if not flags_found:
    print("No major red flags found.")

print("-" * 50)

