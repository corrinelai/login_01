import sys
import os

LEDGER_DIR = "./storage"

def get_transaction_log(user):
    transactions = []
    for filename in sorted(os.listdir(LEDGER_DIR)):
        with open(os.path.join(LEDGER_DIR, filename), "r") as f:
            for line in f:
                parts = line.strip().split(", ")
                if len(parts) == 3:
                    sender, receiver, amount = parts
                    if sender == user or receiver == user:
                        transactions.append(line.strip())
    return transactions

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python app_checkLog.py <User>")
        sys.exit(1)

    user = sys.argv[1]
    logs = get_transaction_log(user)
    print(f"Transaction history for {user}:")
    for log in logs:
        print(log)
