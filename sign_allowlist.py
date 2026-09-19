import base64, datetime, hashlib, json, re, sys
from cryptography.hazmat.primitives.asymmetric import ed25519

try:
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(open("private.key").read()))
except OSError:
    print("private.key not found. Run 1_FIRST_TIME_SETUP.bat first.")
    sys.exit(1)

users, seen = [], set()
for n, line in enumerate(open("users.txt", encoding="utf-8"), 1):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    email, _, exp = line.partition(",")
    email, exp = email.strip().lower(), exp.strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        print(f"users.txt line {n}: '{email}' is not a valid email"); sys.exit(1)
    if exp:
        try: datetime.date.fromisoformat(exp)
        except ValueError:
            print(f"users.txt line {n}: expiry '{exp}' must look like 2027-03-31"); sys.exit(1)
    if email in seen:
        continue
    seen.add(email)
    users.append({"h": hashlib.sha256(email.encode()).hexdigest(), "exp": exp})

payload = {"issued": datetime.date.today().isoformat(), "users": users}
msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
json.dump({"payload": payload, "sig": base64.b64encode(priv.sign(msg)).decode()}, open("allowlist.json", "w"), indent=1)
print(f"allowlist.json created with {len(users)} approved user(s).")
print("Signed OK. Uploading to GitHub next...")
