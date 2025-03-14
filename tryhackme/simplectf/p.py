import argparse
import requests
import hashlib
import os

# Function to clear the terminal screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to crack the password using a wordlist
def crack_password(url, wordlist):
    try:
        with open(wordlist, "r", encoding="latin-1") as dict_file:
            for line in dict_file:
                line = line.strip()
                salted_hash = hashlib.md5((salt + line).encode()).hexdigest()
                if salted_hash == password:
                    print(f"[+] Password found: {line}")
                    return
    except FileNotFoundError:
        print(f"[!] Wordlist file '{wordlist}' not found.")
        return
    print("[-] Password not found in the wordlist.")

# Argument parsing
parser = argparse.ArgumentParser(description="CMS login cracker.")
parser.add_argument('-u', '--url', required=True, help="Base target URI (ex. http://10.10.10.100/cms)")
parser.add_argument('-w', '--wordlist', help="Wordlist for cracking admin password")
parser.add_argument('-c', '--crack', action="store_true", help="Crack password with wordlist")

args = parser.parse_args()

# Clear screen
clear_screen()

print(f"[+] Target URL: {args.url}")

# Start a session
session = requests.Session()
try:
    response = session.get(args.url, timeout=10)
    if response.status_code == 200:
        print("[+] Target is reachable.")
    else:
        print("[!] Target returned a non-200 status code.")
except requests.exceptions.RequestException as e:
    print(f"[!] Failed to reach the target: {e}")
    exit()

# Simulated values for demonstration purposes (replace with actual extraction logic)
salt = "random_salt"
password = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5('password')

if args.crack:
    if args.wordlist:
        print("[+] Starting password cracking...")
        crack_password(args.url, args.wordlist)
    else:
        print("[!] Please specify a wordlist using -w option.")
