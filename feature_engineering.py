import pandas as pd
import os
import re

INPUT_FILE = "sessions.csv"
OUTPUT_FILE = "sessions_enriched.csv"

def extract_tld(sni):
    try:
        if sni and "." in sni:
            return sni.strip().split(".")[-1].lower()
    except:
        pass
    return "unknown"

def parse_tls_version(version_hex):
    try:
        if version_hex.startswith("0x"):
            major = int(version_hex[2:4], 16)
            minor = int(version_hex[4:6], 16)
            return float(f"{major}.{minor}")
    except:
        pass
    return 0.0

def classify_cipher(cipher_hex):
    weak_ciphers = {"0x0004", "0x0005", "0x000a", "0x002f"}
    strong_ciphers = {"0x1301", "0x1302", "0x1303", "0x1304"}
    try:
        ch = cipher_hex.lower()
        if ch in strong_ciphers:
            return "strong"
        elif ch in weak_ciphers:
            return "weak"
        elif ch.startswith("0x13"):
            return "strong"
        elif ch.startswith("0x00"):
            return "weak"
    except:
        pass
    return "unknown"

def bucket_duration(duration):
    try:
        d = float(duration)
        if d < 1:
            return "short"
        elif d < 5:
            return "medium"
        else:
            return "long"
    except:
        return "unknown"

def enrich_features(df):
    df["SNI_TLD"] = df["TLS SNI (Server Name)"].apply(extract_tld)
    df["TLS_Version_Num"] = df["TLS Version"].apply(parse_tls_version)
    df["Cipher_Strength"] = df["TLS Cipher Suite"].apply(classify_cipher)
    df["Is_SNI_Present"] = df["TLS SNI (Server Name)"].apply(lambda x: 0 if str(x).lower() in ["n/a", "unknown", ""] else 1)
    df["Session_Length_Bucket"] = df["Duration (s)"].apply(bucket_duration)
    return df

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[!] File not found: {INPUT_FILE}")
        return

    df = pd.read_csv(INPUT_FILE)
    print(f"[+] Loaded {len(df)} sessions from {INPUT_FILE}")

    df = enrich_features(df)

    df.to_csv(OUTPUT_FILE, index=False)
    print(f"[✅] Enriched dataset saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
