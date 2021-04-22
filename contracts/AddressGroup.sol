/*
 *    Copyright 2021, NTT Communications Corp.
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

pragma solidity >=0.8.0 <0.9.0;

string constant AddressGroup_ContractId = "AddressGroup.sol:AddressGroup";

contract AddressGroup {
    string public constant contractId = AddressGroup_ContractId;
    uint256 public constant contractVersion = 0;

    address public immutable owner;
    address[] public members;
    mapping (address => uint256) private _addressMap;  // address => index of members


    constructor() {
        owner = msg.sender;
        members.push(msg.sender);
        /* index 0 is reserved for owner. code below is commented out because of redundant.
         * _addressMap[msg.sender] = 0;
         */
    }

    function add(address user) public {
        require(owner == msg.sender, "not owner");
        if (user == owner)
            return;  // owner is always available.
        if (_addressMap[user] > 0)
            return;  // already added.
        for (uint idx = 1; idx < members.length; idx ++) {
            if (members[idx] == address(0)) {
                members[idx] = user;
                _addressMap[user] = idx;
                return;
            }
        }
        _addressMap[user] = members.length;
        members.push(user);
    }

    function remove(address user) public {
        require(owner == msg.sender, "not owner");
        require(owner != user, "not permitted");
        uint256 idx = _addressMap[user];
        require(idx > 0, "not registered");
        delete members[idx];
        delete _addressMap[user];
    }

    function clear() public {
        require(owner == msg.sender, "not owner");
        for (uint idx = 1; idx < members.length; idx ++) {
            if (members[idx] == address(0))
                continue;
            delete _addressMap[members[idx]];
            delete members[idx];
        }
        delete members;
        members.push(owner);
    }

    function isMember(address user) public view returns (bool) {
        if (owner == user)
            return true;
        if (user == address(0))
            return false;
        return (_addressMap[user] > 0);
    }

    function listMembers() public view returns (address[] memory) {
        return members;  // may contain address(0)
    }
}
