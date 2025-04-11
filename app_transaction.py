import os
import hashlib
import sys
import random

LEDGER_DIR = "./storage"
MAX_TRANSACTIONS = 5
USERS = ["A", "B", "C"]

def get_latest_block():
    files = sorted(os.listdir(LEDGER_DIR), key=lambda x: int(x.split(".")[0]))
    return files[-1] if files else None

def create_new_block(prev_block):
    new_block_num = int(prev_block.split(".")[0]) + 1 if prev_block else 1
    return f"{new_block_num}.txt"

def calculate_sha256(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def add_transaction(sender, receiver, amount):
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
            f.write(f"Next block: {create_new_block(new_block)}\n")
        latest_block = new_block

    with open(os.path.join(LEDGER_DIR, latest_block), "a") as f:
        f.write(f"{sender}, {receiver}, {amount}\n")

def generate_random_transaction():
    sender = random.choice(USERS)
    receiver = random.choice([u for u in USERS if u != sender])
    amount = random.randint(1, 100)
    return sender, receiver, amount

if __name__ == "__main__":
    if not os.path.exists(LEDGER_DIR):
        os.makedirs(LEDGER_DIR)

    if len(sys.argv) == 4:
        # 手動模式
        sender, receiver, amount = sys.argv[1], sys.argv[2], int(sys.argv[3])
        if sender not in USERS or receiver not in USERS:
            print("Sender and Receiver must be one of A, B, or C")
            sys.exit(1)
        add_transaction(sender, receiver, amount)
        print(f"Transaction recorded: {sender} → {receiver} : {amount}")

    elif len(sys.argv) == 2 and sys.argv[1].isdigit():
        # 自動模式
        count = int(sys.argv[1])
        for _ in range(count):
            sender, receiver, amount = generate_random_transaction()
            add_transaction(sender, receiver, amount)
            print(f"Random transaction: {sender} → {receiver} : {amount}")

    else:
        print("Usage:")
        print("  Manual: python app_transaction.py A B 50")
        print("  Random: python app_transaction.py 100")
        sys.exit(1)
