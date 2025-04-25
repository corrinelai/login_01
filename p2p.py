import os
import hashlib
import random
import socket
import threading
import time

LEDGER_DIR = "./storage"
MAX_TRANSACTIONS = 5
USERS = ["A", "B", "C"]
RECEIVED_HASHES = {}
LOCK = threading.Lock()

# ========= 帳本處理 =========

def ensure_ledger_dir():
    if not os.path.exists(LEDGER_DIR):
        os.makedirs(LEDGER_DIR)

def get_latest_block():
    files = sorted(os.listdir(LEDGER_DIR), key=lambda x: int(x.split(".")[0]))
    return files[-1] if files else None

def create_new_block(prev_block):
    new_block_num = int(prev_block.split(".")[0]) + 1 if prev_block else 1
    return f"{new_block_num}.txt"

def calculate_sha256(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def generate_random_transaction():
    sender = random.choice(USERS)
    receiver = random.choice([u for u in USERS if u != sender])
    amount = random.randint(1, 100)
    return sender, receiver, amount

def add_transaction(sender, receiver, amount):
    ensure_ledger_dir()
    latest_block = get_latest_block()
    if not latest_block:
        latest_block = create_new_block(None)
        with open(os.path.join(LEDGER_DIR, latest_block), "w") as f:
            f.write("Sha256 of previous block: none\n")
            f.write("Next block: 2.txt\n")
    block_path = os.path.join(LEDGER_DIR, latest_block)
    with open(block_path, "r") as f:
        lines = f.readlines()
    if len(lines) - 2 >= MAX_TRANSACTIONS:
        new_block = create_new_block(latest_block)
        prev_hash = calculate_sha256(block_path)
        with open(os.path.join(LEDGER_DIR, new_block), "w") as f:
            f.write(f"Sha256 of previous block: {prev_hash}\n")
            f.write(f"Next block: {int(new_block.split('.')[0]) + 1}.txt\n")
        latest_block = new_block
    with open(os.path.join(LEDGER_DIR, latest_block), "a") as f:
        f.write(f"{sender}, {receiver}, {amount}\n")

def check_money(user):
    total = 0
    for filename in sorted(os.listdir(LEDGER_DIR), key=lambda x: int(x.split(".")[0])):
        with open(os.path.join(LEDGER_DIR, filename), "r") as f:
            lines = f.readlines()[2:]
            for line in lines:
                parts = line.strip().split(", ")
                if len(parts) == 3:
                    sender, receiver, amount = parts
                    amount = int(amount)
                    if sender == user:
                        total -= amount
                    elif receiver == user:
                        total += amount
    print(f"Total balance for {user}: {total}")

def check_log(user):
    print(f"Transaction history for {user}:")
    for filename in sorted(os.listdir(LEDGER_DIR), key=lambda x: int(x.split(".")[0])):
        with open(os.path.join(LEDGER_DIR, filename), "r") as f:
            lines = f.readlines()[2:]
            for line in lines:
                parts = line.strip().split(", ")
                if len(parts) == 3:
                    sender, receiver, _ = parts
                    if sender == user or receiver == user:
                        print(line.strip())

def check_chain(target_user):
    block_files = sorted(os.listdir(LEDGER_DIR), key=lambda x: int(x.split(".")[0]))
    for i in range(1, len(block_files)):
        prev_path = os.path.join(LEDGER_DIR, block_files[i - 1])
        curr_path = os.path.join(LEDGER_DIR, block_files[i])
        prev_hash = calculate_sha256(prev_path)
        with open(curr_path, "r") as f:
            lines = f.readlines()
        if lines[0].strip() != f"Sha256 of previous block: {prev_hash}":
            print(f"❌ 區塊 {block_files[i]} 的前向 hash 不正確")
            return
        expected_next = f"Next block: {int(block_files[i].split('.')[0]) + 1}.txt"
        if lines[1].strip() != expected_next:
            print(f"❌ 區塊 {block_files[i]} 的下一個區塊鏈接不正確")
            return
    latest_block = block_files[-1]
    latest_path = os.path.join(LEDGER_DIR, latest_block)
    with open(latest_path, "r") as f:
        lines = f.readlines()
    if len(lines) - 2 >= MAX_TRANSACTIONS:
        new_block = create_new_block(latest_block)
        prev_hash = calculate_sha256(latest_path)
        with open(os.path.join(LEDGER_DIR, new_block), "w") as f:
            f.write(f"Sha256 of previous block: {prev_hash}\n")
            f.write(f"Next block: {int(new_block.split('.')[0]) + 1}.txt\n")
            f.write(f"angel, {target_user}, 10\n")
    else:
        with open(latest_path, "a") as f:
            f.write(f"angel, {target_user}, 10\n")
    print("✅ Blockchain integrity OK")
    print(f"✅ angel → {target_user} : 10 已成功加入帳本")

def reward_initiator(user):
    block_files = sorted(os.listdir(LEDGER_DIR), key=lambda x: int(x.split(".")[0]))
    latest_block = block_files[-1]
    latest_path = os.path.join(LEDGER_DIR, latest_block)
    with open(latest_path, "r") as f:
        lines = f.readlines()
    if len(lines) - 2 >= MAX_TRANSACTIONS:
        new_block = create_new_block(latest_block)
        prev_hash = calculate_sha256(latest_path)
        with open(os.path.join(LEDGER_DIR, new_block), "w") as f:
            f.write(f"Sha256 of previous block: {prev_hash}\n")
            f.write(f"Next block: {int(new_block.split('.')[0]) + 1}.txt\n")
            f.write(f"angel, {user}, 100\n")
    else:
        with open(latest_path, "a") as f:
            f.write(f"angel, {user}, 100\n")
    print(f"✅ Verification complete. Rewarded angel → {user} : 100")

def verify_local_chain():
    block_files = sorted(os.listdir(LEDGER_DIR), key=lambda x: int(x.split(".")[0]))
    for i in range(1, len(block_files)):
        prev = os.path.join(LEDGER_DIR, block_files[i - 1])
        curr = os.path.join(LEDGER_DIR, block_files[i])
        prev_hash = calculate_sha256(prev)
        with open(curr, "r") as f:
            lines = f.readlines()
            if lines[0].strip() != f"Sha256 of previous block: {prev_hash}":
                return False
    return True

# ========= P2P Node =========

class P2PNode:
    def __init__(self, ip, port, peers):
        self.ip = ip
        self.port = port
        self.peers = peers
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def start(self):
        self.sock.bind((self.ip, self.port))
        threading.Thread(target=self._listen, daemon=True).start()
        threading.Thread(target=self._send_commands, daemon=True).start()

    def _listen(self):
        while True:
            data, addr = self.sock.recvfrom(65536)
            msg = data.decode().strip()
            print(f"📩 Received: {msg[:80]}... from {addr}")
            if msg == "CHECK_LAST_BLOCK":
                latest = get_latest_block()
                if latest:
                    block_path = os.path.join(LEDGER_DIR, latest)
                    sha256 = calculate_sha256(block_path)
                    self.sock.sendto(sha256.encode(), addr)
            elif msg.startswith("SYNC_REQUEST"):
                requester_ip, requester_port = msg.split()[1:3]
                self._send_ledger((requester_ip, int(requester_port)))
            elif msg.startswith("SEND_LEDGER"):
                self._receive_ledger(msg)

    def _send_commands(self):
        while True:
            command = input("Enter command: ").strip().split()
            if not command:
                continue
            cmd = command[0]
            if cmd == "transaction":
                if len(command) == 2 and command[1].isdigit():
                    for _ in range(int(command[1])):
                        s, r, a = generate_random_transaction()
                        add_transaction(s, r, a)
                        print(f"Random transaction: {s} → {r} : {a}")
                elif len(command) == 4:
                    add_transaction(command[1], command[2], int(command[3]))
                    print(f"Transaction recorded: {command[1]} → {command[2]} : {command[3]}")
            elif cmd == "checkMoney" and len(command) == 2:
                check_money(command[1])
            elif cmd == "checkLog" and len(command) == 2:
                check_log(command[1])
            elif cmd == "checkChain" and len(command) == 2:
                check_chain(command[1])
            elif cmd == "checkAllChains" and len(command) == 2:
                self.check_all_chains(command[1])
            elif cmd == "syncLedger":
                for peer in self.peers:
                    msg = f"SYNC_REQUEST {self.ip} {self.port}"
                    self.sock.sendto(msg.encode(), peer)
                print("🛰 Sync request sent to peers.")
            else:
                print("Invalid command.")

    def _send_ledger(self, target):
        for filename in sorted(os.listdir(LEDGER_DIR), key=lambda x: int(x.split(".")[0])):
            path = os.path.join(LEDGER_DIR, filename)
            with open(path, "r") as f:
                content = f.read()
            msg = f"SEND_LEDGER {filename}|||{content}"
            self.sock.sendto(msg.encode(), target)

    def _receive_ledger(self, msg):
        parts = msg[len("SEND_LEDGER "):].split("|||")
        if len(parts) != 2:
            print("Invalid ledger format")
            return
        filename, content = parts
        path = os.path.join(LEDGER_DIR, filename)
        with open(path, "w") as f:
            f.write(content)
        print(f"📥 Synced block: {filename}")

    def check_all_chains(self, target_user):
        def handle_response(data, addr):
            sender = f"{addr[0]}:{addr[1]}"
            print(f"🟢 Received SHA256 from {sender}: {data.strip()}")
            with LOCK:
                RECEIVED_HASHES[sender] = data.strip()
            hashes = list(RECEIVED_HASHES.items())
            for i in range(len(hashes)):
                for j in range(i + 1, len(hashes)):
                    result = "Yes" if hashes[i][1] == hashes[j][1] else "No"
                    print(f"[Compare] {hashes[i][0]} vs {hashes[j][0]}: {result}")

        def listen():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", 8002))
            sock.settimeout(2)
            print("🕓 Waiting for responses on UDP 8002 (up to 10s)...")
            start = time.time()
            try:
                while time.time() - start < 10:
                    try:
                        data, addr = sock.recvfrom(4096)
                        handle_response(data.decode(), addr)
                    except socket.timeout:
                        continue
            finally:
                sock.close()

        print("✅ Step1: Sending SHA256 request to all peers...")
        threading.Thread(target=listen).start()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for peer in self.peers:
            sock.sendto(b"CHECK_LAST_BLOCK", peer)
        sock.close()
        time.sleep(12)
        print("✅ Step2: Verifying local blockchain integrity...")
        if verify_local_chain():
            print("✅ Local chain is valid.")
        else:
            print("❌ Local chain verification failed.")
        reward_initiator(target_user)

# ========= Main =========

if __name__ == "__main__":
    my_ip = "172.28.0.2"  # client1
    my_port = 8001
    peers = [("172.28.0.3", 8002), ("172.28.0.4", 8003)]

    ensure_ledger_dir()
    node = P2PNode(ip=my_ip, port=my_port, peers=peers)
    node.start()
    while True:
        pass
