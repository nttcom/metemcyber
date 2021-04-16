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

pragma solidity >=0.8.0 <0.9.0;

import "@openzeppelin/contracts/token/ERC777/ERC777.sol";

string constant CTIToken_ContractId = "CTIToken.sol:CTIToken";

contract CTIToken is ERC777 {

    string public constant contractId = CTIToken_ContractId;
    uint256 public constant contractVersion = 0;
    address public publisher;

    constructor(
        uint256 initialSupply,
        address[] memory defaultOperators
    )
        ERC777("CTIToken", "CTIT", defaultOperators)
    {
        publisher = msg.sender;
        _mint(msg.sender, initialSupply, "", "");
    }

    function mint(
        address dest,
        uint256 amount,
        bytes memory userData,
        bytes memory operatorData
    )
        public
    {
        require(msg.sender == publisher, "not publisher");
        _mint(dest, amount, userData, operatorData);
    }
}
