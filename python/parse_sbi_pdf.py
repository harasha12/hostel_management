import pdfplumber
import sys
import json
import re

pdf_path = sys.argv[1]
transactions = []

def clean_amount(val):
    if not val:
        return None
    val = val.replace(",", "").strip()
    try:
        return float(val)
    except:
        return None

def to_mysql_date(d):
    try:
        dd, mm, yyyy = d.strip().split("/")
        return f"{yyyy}-{mm}-{dd}"
    except:
        return None

with pdfplumber.open(pdf_path) as pdf:
    for page in pdf.pages:
        table = page.extract_table()
        if not table or len(table) < 2:
            continue

        headers = [h.lower().strip() if h else "" for h in table[0]]

        def col_index(name):
            for i, h in enumerate(headers):
                if name in h:
                    return i
            return None

        idx_txn_date = col_index("txn")
        idx_desc = col_index("description")
        idx_ref = col_index("ref")
        idx_debit = col_index("debit")
        idx_credit = col_index("credit")

        if idx_txn_date is None or idx_ref is None:
            continue  # skip invalid tables

        for row in table[1:]:
            if not row or len(row) <= max(idx_ref, idx_txn_date):
                continue

            txn_date_raw = row[idx_txn_date]
            ref_no = row[idx_ref]
            description = row[idx_desc] if idx_desc is not None else ""

            debit = row[idx_debit] if idx_debit is not None else None
            credit = row[idx_credit] if idx_credit is not None else None

            txn_date = to_mysql_date(txn_date_raw)
            if not txn_date or not ref_no:
                continue

            amount = None
            txn_type = None

            credit_amt = clean_amount(credit)
            debit_amt = clean_amount(debit)

            if credit_amt:
                amount = credit_amt
                txn_type = "CREDIT"
            elif debit_amt:
                amount = debit_amt
                txn_type = "DEBIT"
            else:
                continue

            transactions.append({
                "transaction_date": txn_date,
                "bank_ref_no": ref_no.strip(),
                "amount": amount,
                "txn_type": txn_type,
                "description": description.strip()
            })

print(json.dumps(transactions, indent=2))
