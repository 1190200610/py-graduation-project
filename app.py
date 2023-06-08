import json
from flask import Flask, request
import tools
import datetime
import re
import ipaddress
import hashlib
import device

app = Flask(__name__)
w3, contract, contract_address = tools.compile_contract()


def check_access(user_account, user_role, user_org, IIoTID):
    args = [user_account, user_role, user_org, IIoTID]
    tools.construct_transaction(contract, contract_address, 'CheckAccess', args)
    message = contract.functions.CheckAccess(user_account, user_role, user_org, IIoTID).call()
    return message

def test_greet():
    transaction = {
        'to': contract_address,
        'value': 0,
        'gas': 1000000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(w3.eth.accounts[0]),
        'data': contract.encodeABI(fn_name='greet', args=[]),
        'chainId': w3.eth.chain_id,
    }

    signed_transaction = w3.eth.account.sign_transaction(transaction, '0x6e42adf48e59b4e32d157d8dd9e6581da8875539ebea69e49d1b3b3cd8ed908b')
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    print(f"Transaction hash: {transaction_hash.hex()}")

    # 等待交易收据
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    print(f"Transaction receipt: {transaction_receipt}")
    return contract_address


def add_policy(user_name, user_account, user_role, user_org, IIoTID, permission, create_time, end_time, allowed_ip):
    tx_hash = contract.functions.AddPolicy(
        user_name, user_account, user_role, user_org, IIoTID,
        permission, create_time, end_time, allowed_ip).transact({'from': tools.address})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(tx_receipt)


def get_policy(user_account, user_role, user_org, IIoTID):
    r = contract.functions.GetPolicy(user_account, user_role, user_org, IIoTID).call()
    print(r)
    return "Nothing"


def update_policy(user_account, user_role, user_org, IIoTID, permission, create_time, end_time, allowed_ip):
    tx_hash = contract.functions.UpdatePolicy(
        user_account, user_role, user_org, IIoTID,
        permission, create_time, end_time, allowed_ip).transact()
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(tx_receipt)


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


@app.route("/test", methods=["POST", "GET"])
def test():
    r = test_greet()
    print(r)
    return json.dumps({
        "success": True,
        "data": contract_address
    })


@app.route("/login", methods=["POST"])
def login():
    username = request.get_json()
    if username is None:
        print("No Data")
    else:
        print(username)
    return json.dumps({
        "success": True,
        "data": {
            "username": "admin",
            "roles": ["admin"],
            "accessToken": "eyJhbGciOiJIUzUxMiJ9.admin",
            "refreshToken": "eyJhbGciOiJIUzUxMiJ9.adminRefresh",
            "expires": "2023/10/30 00:00:00"
        }
    })


@app.route("/checkAccess", methods=["POST", "GET"])
def checkAccess():
    form = request.get_json()
    userAccount = form['userAddress']
    userRole = form['userRole']
    userOrg = form['userOrg']
    IIoTID = form['IIoTID']
    message = check_access(userAccount, userRole, userOrg, IIoTID)
    return json.dumps({
        "success": True,
        "data": message
    })


@app.route("/addPolicy", methods=["POST", "GET"])
def addPolicy():
    form = request.get_json()
    username = form['username']
    userAddress = form['userAddress']
    userRole = form['userRole']
    userOrg = form['userOrg']
    IIoTID = form['IIoTID']
    permission = form['permission']
    endtime2 = form['endtime1']
    endtime1 = form['endtime2']
    allowedIP = form['allowedIP']
    if tools.is_ethereum_address(userAddress):
        pass
    else:
        return json.dumps({
            "success": True,
            "data": {
                "stat": "1"
            }
        })

    if endtime1 <= endtime2:
        pass
    else:
        return json.dumps({
            "success": True,
            "data": {
                "stat": "2"
            }
        })

    if tools.is_valid_ip_ranges(allowedIP):
        return json.dumps({
            "success": True,
            "data": {
                "stat": "3"
            }
        })
    # ToDo 如果没有查到对应的IIoTID，返回错误信息
    add_policy(username, userAddress, userRole, userOrg, IIoTID, permission, endtime1, endtime2, allowedIP)
    return json.dumps({
        "success": True,
        "data": {
            "stat": "Success"
        }
    })


@app.route("/getAsyncRoutes", methods=["POST", "GET"])
def getAsyncRoutes():
    return json.dumps({
        "success": True,
        "data": []
    })


if __name__ == '__main__':
    app.run(host='192.168.11.1')