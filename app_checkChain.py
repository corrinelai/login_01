import os
import hashlib
import sys

LEDGER_DIR = "./storage"
MAX_TRANSACTIONS = 5

if len(sys.argv) != 2 or sys.argv[1] not in ["A", "B", "C"]:
    print("Usage: python app_checkChain.py <A|B|C>")
    sys.exit(1)

target_user = sys.argv[1]

block_files = sorted(os.listdir(LEDGER_DIR), key=lambda x: int(x.split(".")[0]))

# 區塊鏈驗證
for i in range(1, len(block_files)):
    prev_path = os.path.join(LEDGER_DIR, block_files[i - 1])
    curr_path = os.path.join(LEDGER_DIR, block_files[i])

    with open(prev_path, "rb") as f:
        prev_hash = hashlib.sha256(f.read()).hexdigest()

    with open(curr_path, "r") as f:
        lines = f.readlines()
        first_line = lines[0].strip()
        second_line = lines[1].strip() if len(lines) > 1 else ""

    if first_line != f"Sha256 of previous block: {prev_hash}":
        print(f"❌ 區塊 {block_files[i]} 的前向 hash 不正確")
        sys.exit(1)

    next_block = f"Next block: {int(block_files[i].split('.')[0]) + 1}.txt"
    if second_line != next_block:
        print(f"❌ 區塊 {block_files[i]} 的下一個區塊鏈接不正確")
        sys.exit(1)

print("✅ Blockchain integrity OK")

# 寫入 angel 的交易
latest_block = block_files[-1]
latest_path = os.path.join(LEDGER_DIR, latest_block)

with open(latest_path, "r") as f:
    lines = f.readlines()

transaction_lines = lines[2:]

if len(transaction_lines) >= MAX_TRANSACTIONS:
    # 新區塊建立（靜默處理）
    new_block_num = int(latest_block.split(".")[0]) + 1
    new_block = f"{new_block_num}.txt"
    new_block_path = os.path.join(LEDGER_DIR, new_block)
    prev_hash = hashlib.sha256(open(latest_path, "rb").read()).hexdigest()

    with open(new_block_path, "w") as f:
        f.write(f"Sha256 of previous block: {prev_hash}\n")
        f.write(f"Next block: {new_block_num + 1}.txt\n")
        f.write(f"angel, {target_user}, 10\n")
else:
    with open(latest_path, "a") as f:
        f.write(f"angel, {target_user}, 10\n")

# 最終訊息
print(f"✅ angel → {target_user} : 10 已成功加入帳本")
