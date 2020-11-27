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

pragma solidity >=0.6.0 <0.8.0;

import "truffle/Assert.sol";
import "truffle/DeployedAddresses.sol";
import "../contracts/CTIToken.sol";

contract TestCTIToken {
    function testInitialSupply() public {
        address tokenHolder = tx.origin; // FIXME
        CTIToken token = CTIToken(DeployedAddresses.CTIToken());

        uint256 fact = token.balanceOf(tokenHolder);
        uint256 expected = 10; // see migrations/*_deploy_ctitoken.js

        Assert.equal(fact, expected, "initialSupply mismatch!");
    }
}
