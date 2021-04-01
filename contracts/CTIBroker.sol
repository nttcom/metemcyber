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

import "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import "@openzeppelin/contracts/introspection/IERC1820Registry.sol";
import "./CTIToken.sol";
import "./CTICatalog.sol";

contract CTIBroker is IERC777Recipient {

    event AmountChanged(
        address catalog,
        address token,
        uint256 amount
    );

    IERC1820Registry private _erc1820 =
        IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);
    bytes32 constant private TOKENS_RECIPIENT_INTERFACE_HASH =
        keccak256("ERC777TokensRecipient");

    // catalog address => token address => amount of token consigned.
    mapping (address => mapping (address => uint256)) private _deposit;

    constructor() {
        _erc1820.setInterfaceImplementer(
            address(this), TOKENS_RECIPIENT_INTERFACE_HASH, address(this));
    }

    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external override {}

    function consignToken(
        address catalogAddress,
        address tokenAddress,
        uint256 amount
    ) public {
        require(amount > 0, "invalid amount");
        require(
            CTIToken(tokenAddress).publisher() == msg.sender,
            "not token publisher"
        );
        CTICatalog.Cti memory cti =
            CTICatalog(catalogAddress).getCtiInfoByAddress(tokenAddress);
        require(cti.tokenId > 0, "not a published token");
        require(cti.owner == tx.origin, "not owner");

        // Note: token owner should authorize me as operator in advance.
        CTIToken(tokenAddress).operatorSend(
            tx.origin, address(this), amount, "", "");
        _deposit[catalogAddress][tokenAddress] += amount;

        emit AmountChanged(
            catalogAddress,
            tokenAddress,
            _deposit[catalogAddress][tokenAddress]
        );
    }

    function takebackToken(
        address catalogAddress,
        address tokenAddress,
        uint256 amount
    ) public {
        CTICatalog.Cti memory cti =
            CTICatalog(catalogAddress).getCtiInfoByAddress(tokenAddress);
        require(cti.owner == tx.origin, "not owner");
        require(_deposit[catalogAddress][tokenAddress] >= amount,
            "too much amount");
        _deposit[catalogAddress][tokenAddress] -= amount;
        if (_deposit[catalogAddress][tokenAddress] <= 0)
            delete _deposit[catalogAddress][tokenAddress];
        CTIToken(tokenAddress).send(tx.origin, amount, "");

        emit AmountChanged(
            catalogAddress,
            tokenAddress,
            _deposit[catalogAddress][tokenAddress]
        );
    }

    function buyToken(
        address catalogAddress,
        address tokenAddress,
        bool allow_cheaper
    ) public payable {
        require(CTICatalog(catalogAddress).validatePurchase(msg.sender), "You can't access the catalog");
        CTICatalog.Cti memory cti =
            CTICatalog(catalogAddress).getCtiInfoByAddress(tokenAddress);
        uint256 paid = msg.value;
        uint256 price = cti.price * 1e18;  //PTS_RATE: 1pts = ?? wei
        int256 change = int256(msg.value - price);
        if (paid < price)
            revert("short of ETH");
        else if (price < paid && !allow_cheaper)
            revert("paid too much");
        if (_deposit[catalogAddress][tokenAddress] < 1)
            revert("soldout");

        bool succeeded;
        bytes memory _data;
        (succeeded, _data) = (payable(cti.owner)).call{value: price}("");
        require(succeeded, "sending ETH failed");
        CTIToken(tokenAddress).send(tx.origin, 1, "");
        _deposit[catalogAddress][tokenAddress] -= 1;
        if (_deposit[catalogAddress][tokenAddress] <= 0)
            delete _deposit[catalogAddress][tokenAddress];
        if (change > 0) {
            (succeeded, _data) = tx.origin.call{value: uint256(change)}("");
            require(succeeded, "sending change failed");
        }

        emit AmountChanged(
            catalogAddress,
            tokenAddress,
            _deposit[catalogAddress][tokenAddress]
        );
    }

    function getAmounts(
        address catalogAddress,
        address[] memory tokenAddresses
    ) public view returns (uint256[] memory) {
        if (tokenAddresses.length == 0)
            return new uint256[](0);
        uint256[] memory amounts = new uint256[](tokenAddresses.length);
        for (uint8 i = 0; i < tokenAddresses.length; i++) {
            amounts[i] = _deposit[catalogAddress][tokenAddresses[i]];
        }
        return amounts;
    }
}
