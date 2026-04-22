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

try:
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
        url = "https://funbiz.sinopac.com/QPay.WebAPI/api/Nonce" # 正式環境 上面的不確定是甚麼
        headers = {"X-KEYID": XKeyID}
        req_param = {
            "ShopNo": shop_no
        }
        
        response = requests.post(url=url, headers=headers, json=req_param).json()
        
        return str(response["Nonce"])

    def get_aes_iv(nonce):
        return hashlib.sha256(nonce.encode('UTF-8')).hexdigest().upper()[-16:]

    def get_rand_part_str(will_paid):
        rand_part = 9
        gen_digit = 6

        if(will_paid):
            while rand_part % 10 == 9:
                rand_part = randrange(0, 10**((gen_digit-1)+1))
        else:
            rand_part = randrange(0, 10**(gen_digit-1))*10 + 9
        return "{:000006}".format(rand_part)

    # 產生隨機訂單號碼
    def gen_order_no(will_paid = True):
        today = date.today()
        year = today.year
        month = today.month

        order_no = "A{}{:02}{}".format(year, month, get_rand_part_str(will_paid))
        return order_no

    # print(gen_order_no(True))
    # print(gen_order_no(True))
    # print(gen_order_no(True))
    # print(gen_order_no(False))
    # print(gen_order_no(False))
    # print(gen_order_no(False))

    # Output: A202207648185
    # Output: A202207103273
    # Output: A202207593012
    # 以下尾數都是9
    # Output: A202207293259
    # Output: A202207283409
    # Output: A202207971629

    def gen_expire_date(days = 10):
        expire_date = datetime.now() + timedelta(days=days)
        return expire_date.strftime("%Y%m%d")

    # print(gen_expire_date(10))
    # 20220801

    def gen_default_shop_data(will_paid = True, amount = 100):
        tmp_data = {
            "ShopNo": shop_no, 
            # 測試區，需為9表示付費
            # "OrderNo": gen_order_no(will_paid), 
            # 正式區，OrderNo 參數輸入
            "OrderNo": sys.argv[1], 
            "Amount": amount * 100, 
            "CurrencyID": "TWD", 
            "PayType": "",
	    "QRCodeStatus": "Y",
	    "QRCodeSize": 350,
            "ATMParam": { "ExpireDate": "" },
            "CardParam": { },
            "PrdtName": "虛擬帳號訂單", 
            "ReturnURL": "", 
            "BackendURL": ""
        }
        return tmp_data

    def get_message(ori_shop_data, hash_id, iv):
        hash_id_ba = bytearray(hash_id, 'utf-8')

        iv_ba = bytearray(iv, 'utf-8')

        data_string = json.dumps(ori_shop_data, ensure_ascii=False, separators=(',', ':'))
        print(data_string)

        cipher = AES.new(key=hash_id_ba, mode=AES.MODE_CBC, iv=iv_ba)
        message = cipher.encrypt(pad(bytearray(data_string, 'utf-8'), AES.block_size))
        return message.hex().upper()

    def check_passed_rule_param(value):
        if value is None:
            return False
        elif type(value) is dict or type(value) is list:
            return False
        elif type(value) is str and not value.strip():
            return False
        else:
            return True

    def get_sign(ori_shop_data, hash_id, nonce):
        sorted_shop_datat = {key: ori_shop_data.get(key) for key in sorted(ori_shop_data.keys(), key=str.casefold)}
        
        removed_rule_values_shop_data = {key: value for key, value in sorted_shop_datat.items() if check_passed_rule_param(value)}
        
        urlparam = urllib.parse.urlencode(removed_rule_values_shop_data)
        
        urlparam_no_percent_encode = urllib.parse.unquote(urlparam).replace("+", " ")

        final_shop_data = "{}{}{}".format(urlparam_no_percent_encode, nonce, hash_id)
        
        sign = hashlib.sha256(final_shop_data.encode('UTF-8')).hexdigest().upper()
        return sign

    def gen_shop_data_for_atm(will_paid, amount):
        shop_data = gen_default_shop_data(will_paid, amount)

        shop_data["PayType"] = "A"
        shop_data["ATMParam"]["ExpireDate"] = gen_expire_date(expire_days)
        # shop_data["ATMParam"]["ExpireDate"] = gen_expire_date(ExpireDate)
        shop_data["ReturnURL"] = return_url
        shop_data["BackendURL"] = backend_url

        return shop_data

    def create_order_for_atm(nonce, will_paid, amount, expire_days, return_url, backend_url):
        url = "https://api.sinopac.com/funBIZ/QPay.WebAPI/api/Order"
        headers = {"X-KEYID": XKeyID}
        shop_data = gen_shop_data_for_atm(will_paid, amount)
        #print("- shop_data: {}".format(shop_data))
        
        file_name_order = 'OrderLog.txt'
        f3 = open(file_name_order, 'a')        
        print(get_now(), file=f3)
        print("- shop_data: {}".format(shop_data), file=f3)
        print('', file=f3)
        f3.close()
        
        msg = get_message(shop_data, hash_id, iv)
        #print("- msg: "+ msg)

        sign = get_sign(shop_data, hash_id, nonce)
        print("- sign: " + sign)

        req_param = {
            "Version": "1.0.0",
            "ShopNo": shop_no,
            "APIService": "OrderCreate",
            "Sign": sign,
            "Nonce": nonce,
            "Message": msg
        }

        #print("-- Final request: "+ json.dumps(req_param))
        response = requests.post(url=url, headers=headers, json=req_param).json()
        return response

    # 開始實際產生訂單與呼叫
    hash_id = get_hash_id()
    print("- Hash ID: " + hash_id)

    nonce = get_new_nonce()
    print("- Nonce: " + nonce)

    iv = get_aes_iv(nonce)
    print("- IV: " + iv)
    will_paid = True
    
    # amount = 79900
    # amout 改為參數輸入
    amount = int(sys.argv[2])
    # expire_days = 10
    # expire_days 改到config.txt

    # 先暫時使用手冊上的，之後再實作改掉
    # return_url = "http://10.11.22.113:8803/QPay.ApiClient/Store/Return"
    return_url = "https://www.erpkc.com/wh/ERP/WR/BOP.asp"
    backend_url = "https://www.erpkc.com/wh/erp/wr/SINOReturn.asp"
    # backend_url = "https://www.erpkc.com/wh/login.asp"
    # backend_url= ""
    resp = create_order_for_atm(nonce, will_paid, amount, expire_days, return_url, backend_url)
    print("-- Response: " + str(resp))

    def aes_dec(data_string, resp_nonce):
        hash_id_ba = hash_id.encode("utf-8")
        iv_ba = get_aes_iv(resp_nonce).encode("utf-8")
        cipher = AES.new(key=hash_id_ba, mode=AES.MODE_CBC, iv=iv_ba)

        message = bytes.decode(unpad(cipher.decrypt(bytes.fromhex(data_string)), AES.block_size), "utf-8")
        return message

    resp_nonce = resp["Nonce"]
    resp_msg = resp["Message"]
    resp_ori_sign = resp["Sign"]
    
    

    dec = aes_dec(resp_msg, resp_nonce)
    print("- Decryption of Response: {}".format(dec))
    # - Decryption of Response: {"OrderNo":"A202207641740","ShopNo":"NA0322_001","TSNo":"NA032200000004","Amount":7990000,"Status":"S","Description":"S0000 – 處理成功
    # ","PayType":"A","ATMParam":{"AtmPayNo":"99922530245813","WebAtmURL":"https://sandbox.sinopac.com/QPay.WebPaySite/Bridge/PayWebATM?TD=NA032200000004&TK=1edf6be0-deef-480c-b565-3f26157686fe","OtpURL":"https://sandbox.sinopac.com/QPay.WebPaySite/Bridge/PayOTP?TD=NA032200000004&TK=1edf6be0-deef-480c-b565-3f26157686fe"}}

    resp_json = json.loads(dec)
    resp_gen_sign = get_sign(resp_json, hash_id, resp_nonce)

    # print("- 重新產生Sign值: {}".format(resp_gen_sign))
    # Output: - 重新產生Sign值: BC56A381448A021466EC6796361650ACDC3E1B50F4E03A6B1470910B3BB55059

    print("- Sign驗證結果，是否相同? {}".format(resp_ori_sign == resp_gen_sign))
    # Output: - Sign驗證結果，是否相同? True

    tsno = resp_json["TSNo"]
    # print(tsno)
    # Output: NA032200000008

    status = resp_json["Status"]
    # print(status)
    # Output: S

    desc = resp_json["Description"]
    print(desc)
    # Output:  S0000 – 處理成功
    
    atm_param = resp_json["ATMParam"]

    atm_pay_no = atm_param["AtmPayNo"]
    # print(atm_pay_no)
    # Output: 99922530245817

    web_atm_url = atm_param["WebAtmURL"]
    # print(web_atm_url)
    # Output: https://sandbox.sinopac.com/QPay.WebPaySite/Bridge/PayWebATM?TD=NA032200000008&TK=0d5cd0c0-1a88-4b79-a9a7-646eb47146d6

    # otp_url = atm_param["OtpURL"]
    QRCodeURL = resp_json["QRCodeURL"]
    # print(otp_url)
    # Output: https://sandbox.sinopac.com/QPay.WebPaySite/Bridge/PayOTP?TD=NA032200000008&TK=0d5cd0c0-1a88-4b79-a9a7-646eb47146d6

    # json_array = json.loads(dec)
    conn = pyodbc.connect('Driver={SQL Server};'
                      'Server=www.erpkc.com,1434;'
                      'Database=WH;'
					  'UID=coffee;'
                      'PWD=1234@asdf;')
    cursor = conn.cursor()
    cursor.execute(f'''
                UPDATE 繳費單
                SET tsno = '{tsno}'
                ,atm_pay_no = '{atm_pay_no}'
                ,web_atm_url = '{web_atm_url}'
                ,QRCodeURL = '{QRCodeURL}'
                WHERE 單號 = '{sys.argv[1]}'
                ''')
    conn.commit()

    file_name = 'output_append.txt'
    f = open(file_name, 'a')
    print(get_now(), file=f)
    print("OrderNo:" + sys.argv[2], file=f)
    print('tsno:' + tsno, file=f)
    print('status:' + status, file=f)
    print('desc:' + desc, file=f)
    print('atm_pay_no:' + atm_pay_no, file=f)
    print('web_atm_url:' + web_atm_url, file=f)
    # print('otp_url:' + otp_url, file=f)
    print('QRCodeURL:' + QRCodeURL, file=f)
    print('', file=f)
    f.close()

    file_name2 = 'output_only_1data.txt'
    f1 = open(file_name2, 'w')
    print(get_now(), file=f1)
    print("OrderNo:" + sys.argv[2], file=f1)
    print('tsno:' + tsno, file=f1)
    print('status:' + status, file=f1)
    print('desc:' + desc, file=f1)
    print('atm_pay_no:' + atm_pay_no, file=f1)
    print('web_atm_url:' + web_atm_url, file=f1)
    # print('otp_url:' + otp_url, file=f1)
    print('QRCodeURL:' + QRCodeURL, file=f1)
    print('', file=f1)
    f1.close()

except Exception as err:
    print(err)
    Error_log = 'Error_log.txt'
    f2 = open(Error_log, 'a')
    print(get_now(), file=f2)
    print(err, file=f2)
    #print(desc, file=f2)
    print('\n', file=f2)
    f2.close()