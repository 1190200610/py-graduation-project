from web3 import Web3
from solcx import compile_source
import tools
import json
import queue
from eth_account import Account
from eth_utils import decode_hex, encode_hex
from eth_account.messages import encode_defunct
import threading
import time

private_key = '0x78683d62ec0b79dcd6064020491fbfe2e536f8f6138ab6c711eb4eb1b3523d24'
public_key = tools.import_public_key_from_private_key(private_key)
address = 0x3e4A6B4Ca26B105d60EF69ce2da05AE0FB7AfAd6
contract_address = '0x1cafDA716d755963a6E36b526D2C364D4221fe5E'
signed_events_queue = queue.Queue()

class GetToken:
    def __init__(self, UserAccount, UserRole, UserOrg, IIoTID, Permission, CreateTime, EndTime, AllowedIP):
        self.UserAccount = UserAccount
        self.UserRole = UserRole
        self.UserOrg = UserOrg
        self.IIoTID = IIoTID
        self.Permission = Permission
        self.CreateTime = CreateTime
        self.EndTime = EndTime
        self.AllowedIP = AllowedIP


def parse_and_sign_event(event, private_key):
    # 解析事件数据
    token_data = GetToken(
        UserAccount=event['args']['UserAccount'],
        UserRole=event['args']['UserRole'],
        UserOrg=event['args']['UserOrg'],
        IIoTID=event['args']['IIoTID'],
        Permission=event['args']['Permission'],
        CreateTime=event['args']['CreateTime'],
        EndTime=event['args']['EndTime'],
        AllowedIP=event['args']['AllowedIP']
    )

    # 将事件数据转换为 JSON
    token_data_json = json.dumps(token_data.__dict__, ensure_ascii=False)

    # 使用私钥签名事件数据
    signer = Account.from_key(private_key)
    message = encode_defunct(text=token_data_json)
    signed_message = signer.sign_message(message)

    # 将签名的事件数据加入队列
    signed_events_queue.put({
        'event_data': token_data,
        'signature': encode_hex(signed_message.signature)
    })

    print(f"Signed event added to the queue: {encode_hex(signed_message.signature)}")


def remove_event_from_queue(signed_event):
    with signed_events_queue.mutex:
        try:
            signed_events_queue.queue.remove(signed_event)
            print(f"Event removed from the queue: {signed_event}")
        except ValueError:
            print(f"Event not found in the queue: {signed_event}")


def watch_GetToken():
    f = open("superAdministrator.sol", encoding="utf-8")
    source = f.read()
    w3 = tools.w3
    tools.test_connnect(w3)
    compiled_sol = compile_source(source, output_values=['abi', 'bin'])
    contract_id, contract_interface = compiled_sol.popitem()
    bytecode = contract_interface['bin']
    abi = contract_interface['abi']

    contract = w3.eth.contract(address=contract_address, abi=abi)
    event_filter = contract.events.GetToken.create_filter(fromBlock='latest')

    print("正在获取事件......")
    while True:
        # 获取事件
        time.sleep(1)
        events = event_filter.get_new_entries()
        for event in events:
            print(event)
            parse_and_sign_event(event, private_key)
            signed_event = signed_events_queue.get()
            data = signed_event['event_data']
            signature = signed_event['signature']
            print(f"Event data: {data}")
            print(f"Signature: {signature}")
            print("------------------------------------------------")

            # 在链上提交Token
            commit_token(data, signature)

            # 创建一个新线程，在6小时后从队列中删除此数据
            timer = threading.Timer(3600 * 6, remove_event_from_queue, args=(signed_event,))
            timer.start()


def commit_token(data, signature):
    contract = tools.w3.eth.contract(address=contract_address, abi=tools.abi)
    args = [data.IIoTID, data.UserAccount, signature]
    tools.construct_transaction(contract, contract_address, 'ReceiveToken', args)
    print('------------------------------------------------')


def verify_token(data):
    user = data['user']
    device = data['device']
    signature = data['signature']
    token = data['token']

    # 查找是否有对应的 signature
    signed_event = None
    with signed_events_queue.mutex:
        for event in signed_events_queue.queue:
            if event['signature'] == signature:
                signed_event = event
                break

    if signed_event:
        event_data = signed_event['event_data']

        # 判断 UserAccount 是否与 user 相同
        if event_data.UserAccount == user:
            # 使用 user 的公钥验证 token 是否为 user 签发的
            # ToDo 通过user在链上获取user对应的公钥
            user_public_key = tools.import_public_key_from_address(user)
            message = encode_defunct(text=json.dumps(token))
            try:
                Account.recover_message(message, signature=decode_hex(signature))
                is_verified = user_public_key == user
                print(f"Token verified: {is_verified}")
                return is_verified
            except Exception as e:
                print(f"Token verification failed: {e}")
                return False
        else:
            print("UserAccount does not match user.")
            return False
    else:
        print("No matching signature found in the queue.")
        return False


if __name__ == '__main__':
    watch_GetToken()