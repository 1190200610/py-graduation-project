from web3 import Web3, Account
from solcx import compile_source
import solcx
import json
import datetime
import re
import ipaddress
import hashlib
from eth_utils import decode_hex, encode_hex
from eth_keys import keys

private_key = '0x6e42adf48e59b4e32d157d8dd9e6581da8875539ebea69e49d1b3b3cd8ed908b'
address = '0x2046c9Dde3ef5e60333b991366244275031E78c5'

address_from = '0x2046c9Dde3ef5e60333b991366244275031E78c5'
address_to = '0x459a50CBFD80aA261b7db4e3fb5E6ec909c8d139'
source = open("superAdministrator.sol", encoding="utf-8").read()
compiled_sol = compile_source(source, output_values=['abi', 'bin'])
contract_id, contract_interface = compiled_sol.popitem()
bytecode = contract_interface['bin']
abi = contract_interface['abi']
w3 = Web3(Web3.HTTPProvider('http://192.168.11.1:23333'))


def compile_contract():
    test_connnect(w3)
    account = w3.eth.account.from_key('0x6e42adf48e59b4e32d157d8dd9e6581da8875539ebea69e49d1b3b3cd8ed908b')
    nonce = w3.eth.get_transaction_count(account.address)
    gas_estimate = w3.eth.estimate_gas({"data": bytecode, "from": account.address})
    transaction = {
        'nonce': nonce,
        'gas': gas_estimate,
        'gasPrice': w3.eth.gas_price,
        'data': bytecode
    }
    signed_transaction = account.sign_transaction(transaction)
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    contract_address = transaction_receipt["contractAddress"]

    print("智能合约已部署，地址为:", contract_address)

    super_administrator = w3.eth.contract(
        address=contract_address,
        abi=abi
    )

    return w3, super_administrator, contract_address


def test_connnect(w3):
    if w3.is_connected():
        print("成功连接到以太坊")
    else:
        print("连接以太坊失败")


def convert_json():
    f = open("superAdministrator.sol", encoding="utf-8")
    contract_source_code = f.read()

    # Compile the contract source code
    compiled_sol = compile_source(contract_source_code)

    # Get the contract interface from the compiled contract
    contract_interface = compiled_sol['<stdin>:Greeter']

    # Save the interface as a JSON file
    with open('SuperAdministrator.json', 'w') as f:
        json.dump(contract_interface, f)


def construct_transaction(contract, contract_address, fn_name, args):

    transaction = {
        'to': contract_address,
        'value': 0,
        'gas': 1000000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(w3.eth.accounts[0]),
        'data': contract.encodeABI(fn_name=fn_name, args=args),
        'chainId': w3.eth.chain_id,
    }
    signed_transaction = w3.eth.account.sign_transaction(transaction, private_key)
    transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    print(f"Transaction hash: {transaction_hash.hex()}")

    # 等待交易收据
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    print(f"Transaction receipt: {transaction_receipt}")


def import_public_key_from_address(user_address):
    return "ToDO"


def sha256(string):
    hash_object = hashlib.sha256(string.encode())
    hex_dig = hash_object.hexdigest()

    return hex_dig


def is_ethereum_address(address: str) -> bool:
    if not re.match(r"^0x[a-fA-F0-9]{40}$", address):
        return False
    else:
        return True


def is_valid_ip_ranges(ip_ranges):
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    ranges = [range.strip() for range in ip_ranges.split(",")]
    for range in ranges:
        if not re.match(pattern, range):
            return False
    for ip in ip_ranges.replace(",", "").split("-"):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False

    return True


def parse_ip_ranges(ip_ranges):
    if is_valid_ip_ranges(ip_ranges) is False:
       return False
    ranges = [range.strip() for range in ip_ranges.split(",")]
    ips = []
    for range in ranges:
        try:
            start_ip, end_ip = range.split("-")
            start_ip = int(''.join(['{:08b}'.format(int(x)) for x in start_ip.split('.')]), 2)
            end_ip = int(''.join(['{:08b}'.format(int(x)) for x in end_ip.split('.')]), 2)
            for ip in range(start_ip, end_ip + 1):
                for ip in ip_ranges.replace(",", "").split("-"):
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        return False
                ips.append('.'.join([str((ip >> (8 * i)) & 0xff) for i in range(4)][::-1]))
        except:
           return False

    return ips


def string_to_bytes32(s: str) -> bytes:
    b = bytes.fromhex(s)
    if len(b) > 32:
        raise ValueError("Input string is too long")

    return b.ljust(32, b'\0')


def bytes32_to_string(b: bytes) -> str:
    s = b.decode().rstrip('\0')

    return s


def xor_strings(s, t):
    s_bytes = bytearray(s, 'utf-8')
    t_bytes = bytearray(t, 'utf-8')
    result = bytearray()
    for i in range(len(s_bytes)):
        result.append(s_bytes[i] ^ t_bytes[i % len(t_bytes)])

    return str(result, 'utf-8')


def convert_time(time_str):
    dt = datetime.datetime.fromisoformat(time_str.replace('Z', '+00:00'))
    timestamp = int(dt.timestamp())

    return timestamp


def import_public_key_from_private_key(private_key: str) -> str:
    private_key_bytes = decode_hex(private_key)
    private_key_obj = keys.PrivateKey(private_key_bytes)
    public_key_obj = private_key_obj.public_key
    public_key_hex = encode_hex(public_key_obj.to_bytes())

    return public_key_hex
