import argparse, subprocess, sys, pathlib

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="certs", help="Output directory")
    ap.add_argument("--cn", default="localhost", help="Common Name (CN)")
    ap.add_argument("--days", type=int, default=365, help="Validity days")
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    cert = out / "cert.pem"
    key = out / "key.pem"

    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key), "-out", str(cert),
        "-days", str(args.days), "-nodes",
        "-subj", f"/CN={args.cn}"
    ]

    try:
        subprocess.check_call(cmd)
    except FileNotFoundError:
        print("ERROR: openssl not found. Install OpenSSL or generate certs another way.", file=sys.stderr)
        sys.exit(1)

    print(f"Generated:\n  {cert}\n  {key}")

if __name__ == "__main__":
    main()
