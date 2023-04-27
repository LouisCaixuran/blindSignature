pragma solidity ^0.8.18;

/*
This contract implement secret transaction
Consider A deposits 1 eth to this smart contract and b withdrawals this 1 eth to complete the transaction, and they
use a string s as their transaction identifier
Traditional transaction make A directly send this 1 eth to B, but this allow direct link between A and B.
Further trasaction introduce a third-party contract to allow A deposit this 1 eth and B withdrawal this 1 eth, to prevent direct link.
However, one can still find connection between A and B,
as deposit and withdraw have coincident when A provides a hashed string, hs to generate key, f(hs),
and B provide s to verify key by verifying key == f(h(s)), while hs = h(s)

This contract allows A to provide blind hash of the string, bhs or bh(s), by using a "blind factor" r
and generate the key, f(bh(s))
Thus B can still verify key by s by verifying key == f(h(s)) == f(bh(s))*r^(-1), and bh(s) != h(s)
This way, either f(h(s)) and f(bh(s)) only occur once, and r is private, 
which make observers unable to connect the deposit and withdrawal together.

Limitation: Multiple deposits are allowed, but only 1 withdraw is allowed to prevent double-spend
Limitation: No lock prevent 2 transaction using the same key(same r + s) if they call this contract the same time
*/
contract BlindSignature{
    bytes32 constant public N = bytes32(uint256(187));
    bytes32 constant public E = bytes32(uint256(7));
    bytes32 constant private D =  bytes32(uint256(23));
    mapping (bytes32 => bool) private Pool; // The key-pool, true indicate this key is used
    uint256 private P = 11;
    uint256 private Q = 17;


    /*
    This function takes a hashed string to deposit 1 eth and signs with the key
    pre-condition: this key must not be used in previous deposit
    param hs - the hashed string
    return key to access this 1 eth
    */
    //parameter s should be a string after hash encryption
    function sign(bytes32 hs) external payable returns(bytes32){
        require(msg.value == 1 ether);
        bytes32 key = largeExp(hs, D, N);
        require(Pool[key] == false); 

        return key;
    }

    /*
    This function takes the RSA algorithm to blind-hash the string s with blind factor r
    pre-condition: r must be coprime with N, and hence need to be coprime with P and Q
    This function can be done locally with public N and E
    param s - the original string, the transaction identifier
    param r - the "blind factor"
    return the blind hash of s, namely bhs
    */
    //get blind hash (can be done locally)
    function getBlindHash(bytes3 s, uint256 r) external returns(bytes32){
        require (r % P != 0);
        require (r % Q != 0);
        require (r > uint256(1));
        require (r < uint256(N));
        bytes32 hashS = getHash(s);
        uint256 tmp1 = uint256(largeExp(bytes32(r),E,N));
        uint256 tmp2 = uint256(uint256(hashS) % uint256(N));
        return bytes32((tmp1 * tmp2) % uint256(N));
    }

    /*
    This function withdrawals the deposited 1 eth to whom with the corresponding key
    pre-condition: this key must be used in previous deposit
    pre-condition: this key must match with s
    param s - the original string, the transaction identifier
    param key - the key for this deposit
    return true if deposited 1 eth withdrawals successfully
    */
    function pay(bytes3 s, bytes32 key) external returns(bool){
        require(Pool[key] == false);
        bytes32 hash = getHash(s);
        require(largeExp(hash, D, N) == key);
        Pool[key] == true;
        address payable buyer = payable(msg.sender);
        return buyer.send(1 ether);
    }

    /*
    This function takes the RSA algorithm to decrypt given key with given blind factor r
    This function can be done locally with public N and E
    param blind - the "blind hashed" key
    param r - the "blind factor"
    return the original string, the transaction identifier
    */
    function decodeBlindKey(bytes32 blind, uint256 r) external pure returns(bytes32){
        uint256 re = 1; // the inverse of r in module N
        while(re < uint256(N) && (re * r) % uint256(N) != 1){
            re = re + 1;
        }
        return bytes32((uint256(blind) * re) % uint256(N));
        //return re;
    }

    /*
    This function hash the given string with sha-256 standard
    This function can be done locally with same sha-256 standard
    param s - the original string
    return the hashed string
    */
    //hash encryption (can be done locally)
    function getHash(bytes3 s) public pure returns(bytes32){
        return keccak256(abi.encodePacked(s));
    }

    /*
    This function checks if this key is used to withdrawal, thus preventing it from double-spend
    This function can be checked by anyone
    param key - the key for this deposit
    return true if this key is used
    */
    function checkPool(bytes32 key) external view returns(bool){
        return Pool[key];
    }

    /*
    This function use the package in remix to calculate modulus of large exponent
    This function can be done locally
    param base - the base of power
    param exponent - the exponent of power
    param modulus - the modulus
    return the result of (base ^ exponent % modulus)
    */
    //learn from link:
    //https://docs.klaytn.foundation/content/smart-contract/precompiled-contracts#address-0x05-bigmodexp-base-exp-mod
    function largeExp(bytes32 base, bytes32 exponent, bytes32 modulus) private returns (bytes32 result) {
        assembly {
            let pointer := mload(0x40)

            mstore(pointer, 0x20)
            mstore(add(pointer, 0x20), 0x20)
            mstore(add(pointer, 0x40), 0x20)

            mstore(add(pointer, 0x60), base)
            mstore(add(pointer, 0x80), exponent)
            mstore(add(pointer, 0xa0), modulus)

            let success := call(not(0), 0x05, 0x0, pointer, 0xc0, pointer, 0x20)
            switch success
            case 0 {
                revert(0, 0)
            } default{
                result := mload(pointer)
            }
        }
    }   
}
