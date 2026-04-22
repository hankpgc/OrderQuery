
from email import message
from os import stat
from re import S
import urllib, hashlib, requests, json, re, sys
from urllib import response
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import binascii, datetime
from random import randrange
from datetime import date, timedelta, datetime
import pyodbc 

# 環境選擇
USE_PRODUCTION = True  # True = 正式環境，False = 測試環境
 
API_URL   = "https://funbiz.sinopac.com/QPay.WebAPI/api/Order"       if USE_PRODUCTION else "https://apisbx.sinopac.com/funBIZ/QPay.WebAPI/api/Order"
NONCE_URL = "https://funbiz.sinopac.com/QPay.WebAPI/api/Nonce"       if USE_PRODUCTION else "https://apisbx.sinopac.com/funBIZ/QPay.WebAPI/api/Nonce"



# 商店資訊 config.txt
def filter_configtxt(data01, get_index):
    data01 = data01.split('=')[get_index].splitlines(keepends=False)[0]
    return(data01)

def get_now():
    now = datetime.now()
    current_time = now.strftime("%Y/%m/%d %H:%M:%S")
    return current_time

with open('config.txt', 'r') as f:
    lines = f.readlines()

for line in lines:
    if re.search("X-KeyID=", line):
        XKeyID = filter_configtxt(line, 1)
    elif re.search("shop_no=", line):
        shop_no = filter_configtxt(line, 1)
    elif re.search("A1=", line):
        A1 = filter_configtxt(line, 1)
    elif re.search("A2=", line):
        A2 = filter_configtxt(line, 1)
    elif re.search("B1=", line):
        B1 = filter_configtxt(line, 1)
    elif re.search("B2=", line):
        B2 = filter_configtxt(line, 1)  
    elif re.search("expire_days=", line):
        expire_days = int(filter_configtxt(line, 1))

# shop_no = "NA0322_001"
# A1 = "6206EA6AF0D54B9A"
# A2 = "E4F1F928EDEF4A40"
# B1 = "B1573F1EA19E44D2"
# B2 = "DBB58CB15CA64B32"
    
    
    
def bytes_xor_to_hexstring(ba1, ba2):
    return bytes([a ^ b for a, b in zip(ba1, ba2)]).hex()

def get_hash_id():
    ba_xor_A = bytes_xor_to_hexstring(bytes.fromhex(A1), bytes.fromhex(A2))
    ba_xor_B = bytes_xor_to_hexstring(bytes.fromhex(B1), bytes.fromhex(B2))
    return "{}{}".format(ba_xor_A, ba_xor_B).upper()

def get_new_nonce():
    # url = "https://api.sinopac.com/funBIZ/QPay.WebAPI/api/Nonce"
    url = NONCE_URL # 正式環境 上面的不確定是甚麼
    headers = {"X-KEYID": XKeyID}
    req_param = {
        "ShopNo": shop_no
    }
    
    response = requests.post(url=url, headers=headers, json=req_param).json()
    
    return str(response["Nonce"])

def get_aes_iv(nonce):
    return hashlib.sha256(nonce.encode('UTF-8')).hexdigest().upper()[-16:]


def check_passed_rule_param(value):
    if value is None:
        return False
    elif type(value) is dict or type(value) is list:
        return False
    elif type(value) is str and not value.strip():
        return False
    else:
        return True


def get_sign_05(ori_shop_data, hash_id, nonce):
    sorted_shop_datat = {key: ori_shop_data.get(key) for key in sorted(ori_shop_data.keys(), key=str.casefold)}
    
    removed_rule_values_shop_data = {key: value for key, value in sorted_shop_datat.items() if check_passed_rule_param(value)}
    
    urlparam = urllib.parse.urlencode(removed_rule_values_shop_data)
    
    urlparam_no_percent_encode = urllib.parse.unquote(urlparam).replace("+", " ")

    final_shop_data = "{}{}{}".format(urlparam_no_percent_encode, nonce, hash_id)
    
    sign = hashlib.sha256(final_shop_data.encode('UTF-8')).hexdigest().upper()
    return sign
    
def encrypt_message(message_dict, hash_id, iv):

    key = hash_id.encode("utf-8")   # 32 bytes（128-bit 為 16 bytes，此處 HashID 為 32 chars）
    iv_bytes = iv.encode("utf-8")   # 16 bytes
 
    plaintext = json.dumps(message_dict, ensure_ascii=False, separators=(",", ":"))
    cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
    encrypted = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return encrypted.hex().upper()

def decrypt_message(encrypted_hex, hash_id, response_nonce):
    iv = get_aes_iv(response_nonce)
    key = hash_id.encode("utf-8")
    iv_bytes = iv.encode("utf-8")
 
    cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
    decrypted = unpad(cipher.decrypt(bytes.fromhex(encrypted_hex)), AES.block_size)
    return json.loads(decrypted.decode("utf-8"))


# ====================
# 以繳費單號查詢繳費狀態
def query_order_by_order_no(order_no: str) -> dict:
 
    # order_no: 商戶訂單編號（繳費單號），例如 "A202401010001"
    # Returns:  解密後的回應 dict，包含 OrderList
    
    # 查詢條件（Message 明文）
    message_dict = {
        "ShopNo": shop_no,
        "OrderNo": order_no,
    }
 
    # 取得必要參數
    nonce   = get_new_nonce()
    hash_id = get_hash_id()
    iv      = get_aes_iv(nonce)
 
    # 計算簽章與加密
    # sign    = get_sign(message_dict, nonce, hash_id)
    sign = get_sign_05(message_dict, hash_id, nonce)
    message = encrypt_message(message_dict, hash_id, iv)
 
    # 組成最終請求
    payload = {
        "Version":    "1.0.0",
        "ShopNo":     shop_no,
        "APIService": "OrderQuery",
        "Sign":       sign,
        "Nonce":      nonce,
        "Message":    message,
    }
 
    # 送出請求
    resp = requests.post(API_URL, json=payload, timeout=10)
    resp.raise_for_status()
    resp_json = resp.json()
 
    # 解密回應
    response_nonce = resp_json.get("Nonce", "")
    encrypted_msg  = resp_json.get("Message", "")
 
    if not encrypted_msg:
        raise ValueError(f"回應缺少 Message：{resp_json}")
 
    return decrypt_message(encrypted_msg, hash_id, response_nonce)
 
 
# 顯示繳費狀態 
PAY_STATUS_MAP = {
    "1A100": "虛擬帳號建立（待付款）",
    "1A400": "ATM 轉帳完成（已付款）",
    "1A410": "ATM 帳號逾期",
    "1C100": "信用卡待付款",
    "1C200": "信用卡已授權（待請款）",
    "1C400": "信用卡已請款",
    "1F200": "超商付款完成",
    "1M200": "行動支付已授權（待請款）",
    "1M400": "行動支付已請款",
    "1M410": "行動支付逾期取消",
}
 
def print_order_status(result: dict):
    """格式化印出查詢結果"""
    status = result.get("Status")
    desc   = result.get("Description", "")
 
    if status != "S":
        print(f"查詢失敗：{desc}")
        return
 
    order_list = result.get("OrderList", [])
    if not order_list:
        print("查無此訂單")
        return
 
    for order in order_list:
        pay_code = order.get("PayStatus", "")
        pay_desc = PAY_STATUS_MAP.get(pay_code, pay_code)
        print("=" * 50)
        print(f"訂單編號  : {order.get('OrderNo')}")
        print(f"豐收款編號: {order.get('TSNo')}")
        print(f"收款方式  : {order.get('PayType')}")
        print(f"訂單金額  : {int(order.get('Amount', 0)) / 100:.0f} 元")
        print(f"繳費狀態  : {pay_desc}")
        print(f"付款時間  : {order.get('PayDate') or '尚未付款'}")
        print(f"付款截止  : {order.get('ExpireDate', '')}")
        print(f"退款狀態  : {order.get('RefundFlag', 'N')}")
        # 虛擬帳號專屬欄位
        atm = order.get("ATMParam", {})
        if atm.get("AtmPayNo"):
            print(f"虛擬帳號  : {atm.get('AtmPayNo')}")
            print(f"銀行代碼  : {atm.get('BankNo')}")
 

 
if __name__ == "__main__":
    # ORDER_NO = "A202401010001"   # 換成要查詢的繳費單號
    ORDER_NO = sys.argv[1]
    
    print(f"查詢繳費單號：{ORDER_NO}")
    result = query_order_by_order_no(ORDER_NO)
    print_order_status(result)