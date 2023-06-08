import json
import requests
import threading
import tools
import time
import pyDHE
from flask import Flask, request
from eth_account.messages import encode_defunct, defunct_hash_message
from eth_utils import encode_hex, decode_hex
from hexbytes import HexBytes
from eth_account import Account


my_address = '0x459a50CBFD80aA261b7db4e3fb5E6ec909c8d139'
my_role = "1"
my_org = "1"
device_address = '0x3e4A6B4Ca26B105d60EF69ce2da05AE0FB7AfAd6'
contract_address = "0x3F7FB25F422313eBc76F8f476C4c9144D272c893"
private_key = "0x47af68c3c8a2a0f0c1b7b339e65d0b1b73734c8d04285efdb6697ec489ec0190"
public_key = tools.import_public_key_from_private_key(private_key)
device_signature_map = {}
device_token_map = {}
aes_key = "b7a7b140f9d04bc2002c97782b061691589653f093dcea823bb2be7068801e3a"


class EventListenerThread(threading.Thread):
    def __init__(self, web3_instance, contract, user_address, device_address):
        threading.Thread.__init__(self)
        self.w3 = web3_instance
        self.contract = contract
        self.user_address = user_address.lower()
        self.device_address = device_address.lower()
        self.event_triggered = False
        self.event_data = None


    def send_token(self, user, device, signature, token):
        # 通过device的地址查到的IP地址
        url = "http://192.168.11.128:8888/verify"
        headers = {'Content-Type': 'application/json'}
        # ase_key = dh_aes()
        data = {
            # "ase": ase_key,
            "user": user,
            "device": device,
            "signature": signature,
            "token": encode_hex(token)
        }
        response = requests.post(url, data=json.dumps(data), headers=headers)
        # 判断是否已经获取到权限
        print(f"Status Code: {response.status_code}")
        print(f"Response Content: {response.text}")
        verify_token(data)

    def process_event(self, user, device, signature):

        msg_hash = defunct_hash_message(text=signature)
        signed_message = tools.w3.eth.account.signHash(msg_hash, private_key)
        token_to_device = signed_message.signature

        # 存入映射，保存token记录
        # Todo 存入数据库，相当于Cookie
        device_token_map[device] = token_to_device
        device_signature_map[device] = signature
        self.send_token(user, device, signature, token_to_device)

        # # 使用公钥验证签名
        # recovered_address = tools.w3.eth.account._recover_hash(msg_hash, signature=token_to_device)
        # # 检查恢复的地址是否与原始公钥匹配
        # if recovered_address.lower() == public_key.lower():
        #     print("签名验证成功！")
        # else:
        #     print("签名验证失败！")

    def run(self):
        event_filter = self.contract.events.ReToken.create_filter(fromBlock='latest')

        while True:
            while not self.event_triggered:
                time.sleep(0.2)
                for event in event_filter.get_new_entries():
                    user = event['args']['user'].lower()
                    device = event['args']['device'].lower()
                    signature = event['args']['signature']

                    if user == self.user_address and device == self.device_address:
                        self.event_data = {'user': user, 'device': device, 'signature': signature}
                        print("Event data: ", event_listener.event_data)
                        self.process_event(user, device, signature)


def check_access(user_account, user_role, user_org, IIoTID):
    #  在查询之前 先检查是否已经有IIoTID对应的Token存入，如果有，直接发送，获取权限
    url = "http://192.168.11.1:5000/checkAccess"
    headers = {'Content-Type': 'application/json'}
    data = {
            "userAddress": user_account,
            "userRole": user_role,
            "userOrg": user_org,
            "IIoTID": IIoTID
    }
    response = requests.post(url, data=json.dumps(data), headers=headers)
    # 打印 HTTP 状态码和响应内容
    print(f"Status Code: {response.status_code}")
    print(f"Response Content: {response.text}")


def verify_token(data):
    user = data['user']
    device = data['device']
    signature = data['signature']
    token = data['token']
    message = defunct_hash_message(text=signature)
    print(f"共享的AES密钥: {(aes_key)}")
    try:
        # 使用公钥验证签名
        recovered_address = tools.w3.eth.account._recover_hash(message, signature=HexBytes(decode_hex(token)))
        # 检查恢复的地址是否与原始公钥匹配
        if recovered_address.lower() == user.lower():
            print("签名验证成功！")
        else:
            print("签名验证失败！")
    except Exception as e:
        print(f"Token verification failed: {e}")
        return False


def dh_aes():
    alice = pyDHE.new()  # 初始化DH交换
    alice_publicKey = alice.getPublicKey()  # 生成公钥
    url = "http://192.168.11.128:8888/dh"
    headers = {'Content-Type': 'application/json'}
    data = {
        "alice_publicKey": alice_publicKey
    }
    response = requests.post(url, data=json.dumps(data), headers=headers)
    # 打印 HTTP 状态码和响应内容
    print(f"Status Code: {response.status_code}")
    print(f"Response Content: {response.text}")
    shared_secret_alice = alice.update(response.text)
    return shared_secret_alice


if __name__ == '__main__':
    tools.test_connnect(tools.w3)
    contract = tools.w3.eth.contract(address=contract_address, abi=tools.abi)

    # 创建并启动事件监听线程
    event_listener = EventListenerThread(tools.w3, contract, my_address, device_address)
    event_listener.start()
    print("正在获取 Token ......")
    check_access(my_address, my_role, my_org, IIoTID="1")
