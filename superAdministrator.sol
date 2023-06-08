// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SuperAdministrator {

    string public greeting = "Hello World";
    struct Header {
        string algorithm;
        string typ;
    }

    struct Payload {
        string tokenIssuer;
        string tokenUser;
        string issuedTime;
        string expTime;
    }

    struct ABACPolicy {
        string Username;
        string UserAccount;
        string UserRole;
        string UserOrg;
        string IIoTID;
        string Permission;
        string CreateTime;
        string EndTime;
        string AllowedIP;
    }

    event GetToken(
        string UserAccount,
        string UserRole,
        string UserOrg,
        string IIoTID,
        string Permission,
        string CreateTime,
        string EndTime,
        string AllowedIP
    );

    event ReToken (
        address user,
        address device,
        string signature
    );

    event Test_event(
        string test_string,
        uint test_uint
    );

    uint numHeaders = 0;
    uint numPayloads = 0;
    address private owner = 0x2046c9Dde3ef5e60333b991366244275031E78c5;
    mapping(bytes32 => ABACPolicy) private PolicyList;
    mapping(bytes32 => Header) private HeaderList;
    mapping(bytes32 => Payload) private PayloadList;
    mapping(string => address) private IIoTIDtoAddress;
    mapping(address => string) private AddresstoIP ;
    mapping(string => string) private IIoTIDtoIP;
    mapping(string => string) private UserAddresstoPublicKey;



    constructor() {
        IIoTIDtoAddress["1"] = 0x3e4A6B4Ca26B105d60EF69ce2da05AE0FB7AfAd6;
        IIoTIDtoAddress["2"] = 0xC71b9a32f0a7A34977f8A45C207AC6143FE41553;
        AddPolicy("test", "0x459a50CBFD80aA261b7db4e3fb5E6ec909c8d139", "1","1", "1", "allow","1","100","*");
        UserAddresstoPublicKey['0x459a50CBFD80aA261b7db4e3fb5E6ec909c8d139d'] = '0x1521f8667aa9fbd62e232088d4414b7b3520da1331647fbbf302713498c9ebc66a801b43fdd22c9de93efcb025c915c33b24715331a8bd9cf0c98e705314b78c';
    }

    function CheckAccess(
        string memory UserAccount, string memory UserRole,
        string memory UserOrg, string memory IIoTID
    ) external returns (string memory) {
        bytes32 id = sha256(abi.encode(stringToBytes32(string.concat(UserOrg, UserRole, IIoTID, UserAccount))));
        ABACPolicy memory policy = PolicyList[id];
        if (!CheckPolicy(policy)){
            return "Policy not exists!";
        } else {
            emit GetToken(
                UserAccount, UserRole, UserRole, IIoTID, policy.Permission,
                policy.CreateTime, policy.EndTime, policy.AllowedIP);
            return "Generating token please accept...";
        }
    }

    function greet() public returns (string memory) {
        emit Test_event(greeting, 1);
        return greeting;
    }

    function ReceiveToken(string memory IIoTID, address user, string memory signature) public returns (string memory) {
        address device = getIIoTIDtoAddress(IIoTID);
        emit ReToken(user, device, signature);
        return "Returning token please accept...";
    }


    function addIIoTIDtoAddress(string memory key, address value) private{
        require(
            msg.sender == owner,
            "Only SuperAdministrator can give right to operate."
            );
        IIoTIDtoAddress[key] = value;
    }


    function getIIoTIDtoAddress(string memory key) public view returns (address){
        require(
            msg.sender == owner,
            "Only SuperAdministrator can give right to operate."
            );
        return IIoTIDtoAddress[key];
    }


    function updateIIoTIDtoAddress(string memory key, address value) private {
         require(
            msg.sender == owner,
            "Only SuperAdministrator can give right to operate."
            );
        IIoTIDtoAddress[key] = value;
    }


    function stringToBytes32(string memory _str) public pure returns (bytes32) {
        bytes memory tempBytes = bytes(_str);
        bytes32 convertBytes;
        if (0 == tempBytes.length)
            return 0x0;
        assembly {
            convertBytes := mload(add(_str, 32))
        }
        return convertBytes;
    }

    function bytes32ToString(bytes32 _bytes32) public pure returns (string memory) {
        uint8 i = 0;
        while(i < 32 && _bytes32[i] != 0) {
            i++;
        }
        bytes memory bytesArray = new bytes(i);
        for (i = 0; i < bytesArray.length; i++) {
            bytesArray[i] = _bytes32[i];
        }
        return string(bytesArray);
    }


    function CheckPolicy(ABACPolicy memory policy) public pure returns (bool) {
        if (keccak256(abi.encode(policy.CreateTime)) == keccak256(abi.encode("")) ||
         keccak256(abi.encode(policy.EndTime)) == keccak256(abi.encode(""))) {
            return false;
        }
        if (keccak256(abi.encode(policy.Permission)) == keccak256(abi.encode(""))) {
            return false;
        }
        return true;

    }

    function AddPolicy(
        string memory Username, string memory UserAccount, string memory UserRole,
        string memory UserOrg, string memory IIoTID, string memory Permission,
        string memory CreateTime, string memory EndTime, string memory AllowedIP) public {
        require(
            msg.sender == owner,
            "Only SuperAdministrator can give right to operate."
            );
        bytes32 id = sha256(abi.encode(stringToBytes32(string.concat(UserOrg, UserRole, IIoTID, UserAccount))));
        PolicyList[id].Username = Username;
        PolicyList[id].UserAccount = UserAccount;
        PolicyList[id].UserRole = UserRole;
        PolicyList[id].UserOrg = UserOrg;
        PolicyList[id].IIoTID = IIoTID;
        PolicyList[id].Permission = Permission;
        PolicyList[id].CreateTime = CreateTime;
        PolicyList[id].EndTime = EndTime;
        PolicyList[id].AllowedIP = AllowedIP;
        }

    function GetPolicy(
        string memory UserAccount, string memory UserRole,
        string memory UserOrg, string memory IIoTID) public view returns (
            string memory _Permission, string memory _CreateTime,
            string memory _EndTime, string memory _AllowedIP
        ){
            bytes32 id = sha256(abi.encode(stringToBytes32(string.concat(UserOrg, UserRole, IIoTID, UserAccount))));
            _Permission =  PolicyList[id].Permission;
            _CreateTime =  PolicyList[id].CreateTime;
            _EndTime =  PolicyList[id].EndTime;
            _AllowedIP =  PolicyList[id].AllowedIP;
        }



    function DeletePolicy(string memory UserAccount, string memory UserRole,
        string memory UserOrg, string memory IIoTID) public {
        require(
            msg.sender == owner,
            "Only SuperAdministrator can give right to operate."
            );
        bytes32 id = sha256(abi.encode(stringToBytes32(string.concat(UserOrg, UserRole, IIoTID, UserAccount))));
        delete PolicyList[id];
        }


    function UpdatePolicy (
        string memory UserAccount, string memory UserRole, string memory UserOrg,
        string memory IIoTID, string memory Permission,
        string memory CreateTime, string memory EndTime, string memory AllowedIP
    ) public {
        require(
            msg.sender == owner,
            "Only SuperAdministrator can give right to operate."
            );
        bytes32 id = sha256(abi.encode(stringToBytes32(string.concat(UserOrg, UserRole, IIoTID, UserAccount))));
        DeletePolicy(UserAccount, UserRole, UserOrg, IIoTID);
        PolicyList[id].UserAccount = UserAccount;
        PolicyList[id].UserRole = UserRole;
        PolicyList[id].UserOrg = UserOrg;
        PolicyList[id].IIoTID = IIoTID;
        PolicyList[id].Permission = Permission;
        PolicyList[id].CreateTime = CreateTime;
        PolicyList[id].EndTime = EndTime;
        PolicyList[id].AllowedIP = AllowedIP;
    }


    function setAddressToIP(address _address, string memory _ip) public {
        require(
            msg.sender == owner,
            "Only SuperAdministrator can give right to operate."
            );
        AddresstoIP[_address] = _ip;
    }


    function getIPByAddress(address _address) public view returns (string memory) {
        return AddresstoIP[_address];
    }


    function setIIoTIDtoIP(string memory _IIoTID, string memory _ip) public {
        require(
            msg.sender == owner,
            "Only SuperAdministrator can give right to operate."
            );
        IIoTIDtoIP[_IIoTID] = _ip;
    }


    function getIPByIIoTID(string memory _IIoTID) public view returns (string memory) {
        return IIoTIDtoIP[_IIoTID];

    }

    function setUserAddressToPublicKey(string memory _userAddress, string memory _publicKey) public {
        require(
            msg.sender == owner,
            "Only SuperAdministrator can give right to operate."
            );
        UserAddresstoPublicKey[_userAddress] = _publicKey;
    }


    function getPublicKeyByUserAddress(string memory _userAddress) public view returns (string memory) {
        return UserAddresstoPublicKey[_userAddress];
    }


}

