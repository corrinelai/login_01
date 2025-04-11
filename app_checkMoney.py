#B1029041賴亞彤

import sys
import os

LEDGER_DIR = "./storage"  # 資料夾名稱，確保使用變數

# 檢查是否提供了用戶名稱參數
if len(sys.argv) != 2:
    print("Usage: python app_CheckMoney.py <User>")
    sys.exit(1)

user = sys.argv[1]  # 查詢的用戶名（A / B / C）

total_balance = 0  # 用戶的總餘額

# 遍歷存儲目錄中的所有區塊檔案，並按數字順序排序
for filename in sorted(os.listdir(LEDGER_DIR), key=lambda x: int(x.split(".")[0])):
    with open(os.path.join(LEDGER_DIR, filename), "r") as f:
        lines = f.readlines()

        # 忽略區塊檔案的第一行（SHA256）和第二行（Next block）
        lines = lines[2:]  # 跳過前兩行

        # 遍歷每一筆交易
        for line in lines:
            parts = line.strip().split(", ")
            if len(parts) == 3:
                sender, receiver, amount = parts
                amount = int(amount)  # 將金額轉換為整數

                # 如果用戶是發送者，金額為負
                if sender == user:
                    total_balance -= amount
                # 如果用戶是接收者，金額不變
                elif receiver == user:
                    total_balance += amount

                # 顯示交易紀錄（只顯示該用戶的交易）
                if sender == user or receiver == user:
                    if sender == user:
                        amount = -amount  # 發送者金額為負
                    print(f"{filename}: {sender} → {receiver} : {amount}")


# 顯示該用戶的餘額
print(f"Total balance for {user}: {total_balance}")
