/*
 *    Copyright 2020, NTT Communications Corp.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

// SPDX-License-Identifier: Apache-2.0

pragma solidity >=0.7.0 <0.8.0;
pragma experimental ABIEncoderV2;

library MetemcyberUtil {

    bytes constant private _lowerHexChars = "0123456789abcdef";
    bytes1 constant private _b1_0 = bytes1("0");
    bytes1 constant private _b1_x = bytes1("x");
    bytes1 constant private _b1_X = bytes1("X");
    uint8 constant private _u8_f = uint8(bytes1("f"));
    uint8 constant private _u8_a = uint8(bytes1("a"));
    uint8 constant private _u8_F = uint8(bytes1("F"));
    uint8 constant private _u8_A = uint8(bytes1("A"));
    uint8 constant private _u8_9 = uint8(bytes1("9"));
    uint8 constant private _u8_0 = uint8(bytes1("0"));
    uint8 constant private _u8_toLower = _u8_a - _u8_A;

    function stringToAddress(
        string memory str
    ) public pure returns (address addr) {
        bytes memory bstr = bytes(str); // low-level bytes of UTF8
        uint8 offset = 0;
        uint8 max = 40; // address is 20 byte, 40 letters.
        uint256 ret = 0;

        if (bstr.length == 42) {
            require(bstr[0] == _b1_0 && (bstr[1] == _b1_x || bstr[1] == _b1_X),
                "invalid input");
            offset = 2;
            max += 2;
        } else {
            require(bstr.length == 40, "invalid input length");
        }
        for (uint8 i = offset; i < max; i++) {
            uint8 u8_i = uint8(bstr[i]);
            uint8 tmp;
            if (_u8_a <= u8_i && u8_i <= _u8_f)
                tmp = u8_i - _u8_a + 10;
            else if (_u8_A <= u8_i && u8_i <= _u8_F)
                tmp = u8_i - _u8_A + 10;
            else if (_u8_0 <= u8_i && u8_i <= _u8_9)
                tmp = u8_i - _u8_0;
            else
                revert("invalid input");
            ret = ret * 16 + tmp;
        }
        return address(ret);
    }

    function addressToString(
        address addr
    ) internal pure returns (string memory) {
        bytes memory baddr = abi.encodePacked(addr);
        bytes memory bstr = new bytes(42); // 40 letters + 0x
        bstr[0] = '0';
        bstr[1] = 'x';
        for (uint8 i = 0; i < 20; i++) {
            bstr[2+i*2] = _lowerHexChars[uint256(uint8(baddr[i]) >> 4)];
            bstr[2+i*2+1] = _lowerHexChars[uint256(uint8(baddr[i]) & 0xF)];
        }
        return string(bstr); // lowercase hex string with leading 0x
    }

    function toChecksumAddress(
        string memory addressString
    ) public pure returns (string memory) {
        // for detail, see https://eips.ethereum.org/EIPS/eip-55

        bytes memory blower = _toLower(bytes(addressString));
        bytes memory bhash = _bytes32ToBytes(keccak256(blower));
        bytes memory bfixed = new bytes(42); // 40 letters + 0x
        bfixed[0] = '0';
        bfixed[1] = 'x';
        for (uint8 i = 0; i < 40; i++) {
            if (uint8(blower[i]) <= _u8_9) { // digit
                bfixed[2+i] = blower[i];
                continue;
            }
            uint8 u = uint8(bhash[i/2]);
            if (i % 2 == 0)
                u >>= 4; // higher half
            else
                u &= 0xF; // lower half
            if (u >= 8)
                bfixed[2+i] = bytes1(uint8(blower[i]) - _u8_toLower);
            else
                bfixed[2+i] = blower[i];
        }
        return string(bfixed); // ChecksumAddress conform to EIP-55
    }

    function isSameStrings(
        string memory s1,
        string memory s2
    ) internal pure returns (bool isSame) {
        return (
            keccak256(abi.encodePacked(s1)) == keccak256(abi.encodePacked(s2))
        );
    }

    function _bytes32ToBytes(
        bytes32 source
    ) internal pure returns (bytes memory) {
        bytes memory bstr = new bytes(32);
        for (uint8 i=0; i < 32; i++)
            bstr[i] = source[i];
        return bstr;
    }

    function _toLower(bytes memory bstr) internal pure returns (bytes memory) {
        bytes memory blower = new bytes(40);
        uint8 offset = 0;
        if (bstr.length == 42) {
            require(bstr[0] == _b1_0 && (bstr[1] == _b1_x || bstr[1] == _b1_X),
                "invalid input");
            offset = 2;
        } else {
            require(bstr.length == 40, "invalid input length");
        }
        for (uint8 i = 0; i < 40; i++) {
            uint8 u8_i = uint8(bstr[i + offset]);
            if (_u8_a <= u8_i && u8_i <= _u8_f)
                blower[i] = bstr[i + offset];
            else if (_u8_A <= u8_i && u8_i <= _u8_F)
                blower[i] = bytes1(u8_i + _u8_toLower);
            else if (_u8_0 <= u8_i && u8_i <= _u8_9)
                blower[i] = bstr[i + offset];
            else
                revert("invalid input");
        }
        return blower; // does not have leading '0x'
    }
}
