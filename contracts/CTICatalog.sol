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

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import {CTIToken, CTIToken_ContractId} from "./CTIToken.sol";
import {AddressGroup, AddressGroup_ContractId} from "./AddressGroup.sol";
import {MetemcyberUtil} from "./MetemcyberUtil.sol";

contract CTICatalog is ERC721URIStorage {
    using Counters for Counters.Counter;

    event CtiInfo(
        string tokenURI,
        uint256 tokenId,
        address owner,
        string uuid,
        string title,
        uint256 price,
        string operator
    );

    event CtiLiked(
        string tokenURI,
        uint256 likecount,
        address likeuser
    );

    struct Cti {
        uint256 tokenId; // tokenId in ERC721
        address owner; // owner in ERC721
        string uuid;
        string title;
        uint256 price;
        string operator; // should be address?
        Counters.Counter likecount; // The number of count
    }

    string public constant contractId = "CTICatalog.sol:CTICatalog";
    uint256 public constant contractVersion = 1;
    address public immutable owner;

    Counters.Counter private _tokenIds;
    string[] private _tokenList;
    mapping (string => Cti) private _ctiInfo; // tokenURI => Cti
    mapping (string => uint256) private _ctiIndex; // tokenURI => index
    AddressGroup public members;

    constructor(
        address members_
    ) ERC721("CTICatalog", "CTIC") {
        owner = msg.sender;
        _setMembers(members_);
    }

    function _setMembers(address members_) internal {
        AddressGroup tmp = AddressGroup(members_);
        require(
            members_ == address(0) ||  // public mode
            MetemcyberUtil.isSameStrings(tmp.contractId(), AddressGroup_ContractId),
            "not an address group"
        );
        members = tmp;
    }

    function setMembers(address members_) public {
        require(owner == msg.sender, "not owner");
        _setMembers(members_);
    }

    function publishCti(
        address producer,
        string calldata tokenURI
    ) public returns (uint256) {
        require(this.validatePurchase(msg.sender), "not permitted");
        string memory uri = MetemcyberUtil.toChecksumAddress(tokenURI);
        require(bytes(_ctiInfo[uri].uuid).length > 0, "not registered");
        require(producer == msg.sender, "wrong producer");
        require(_ctiInfo[uri].owner == msg.sender, "not owner");

        _tokenIds.increment();

        uint256 newCtiId = _tokenIds.current();
        _mint(producer, newCtiId);
        _setTokenURI(newCtiId, uri);
        _ctiInfo[uri].tokenId = newCtiId;
        _ctiInfo[uri].owner = ownerOf(newCtiId);

        emit CtiInfo(
            uri,
            _ctiInfo[uri].tokenId,
            _ctiInfo[uri].owner,
            _ctiInfo[uri].uuid,
            _ctiInfo[uri].title,
            _ctiInfo[uri].price,
            _ctiInfo[uri].operator
        );

        return newCtiId;
    }

    function registerCti(
        string calldata tokenURI,
        /* no tokenId */
        /* no owner */
        string calldata uuid,
        string calldata title,
        uint256 price,
        string calldata operator
    ) public {
        require(this.validatePurchase(msg.sender), "not permitted");
        require(bytes(tokenURI).length > 0, "invalid tokenURI");
        CTIToken token = CTIToken(MetemcyberUtil.stringToAddress(tokenURI));
        require(
            MetemcyberUtil.isSameStrings(token.contractId(), CTIToken_ContractId),
            "not a token address"
        );
        require(
            msg.sender == token.publisher(),
            "not token publisher"
        );
        string memory uri = MetemcyberUtil.toChecksumAddress(tokenURI);
        require(
            bytes(_ctiInfo[uri].uuid).length == 0,
            "already registered"
        );
        require(bytes(uuid).length > 0, "invalid uuid");
        require(price >= 0, "invalid price");

        Counters.Counter memory likecount;
        _tokenList.push(uri);
        _ctiInfo[uri] = Cti ({
            tokenId: 0, // given at publishCti
            owner: msg.sender,
            uuid: uuid,
            title: title,
            price: price,
            operator: operator,
            likecount: likecount
        });
        _ctiIndex[uri] = _tokenList.length - 1;
    }

    function modifyCti(
        string calldata tokenURI,
        /* no tokenId */
        /* no owner */
        string calldata uuid,
        string calldata title,
        uint256 price,
        string calldata operator
    ) public {
        require(this.validatePurchase(msg.sender), "not permitted");
        string memory uri = MetemcyberUtil.toChecksumAddress(tokenURI);
        string memory current_uuid = _ctiInfo[uri].uuid;
        require(bytes(current_uuid).length > 0, "not registered");
        require(
            bytes(uuid).length == 0 ||
                MetemcyberUtil.isSameStrings(uuid, current_uuid),
            "invalid uuid"
        );
        require(price >= 0, "invalid price");
        require(_ctiInfo[uri].owner == msg.sender, "not owner");

        { // block to avoid "Stack too deep" error.
            bool modified = false;
            // tokenId should be unmodifiable.
            // owner should be unmodifiable.
            // uuid shold be unmodifiable.
            if (MetemcyberUtil.isSameStrings(_ctiInfo[uri].title, title)
                    == false) {
                _ctiInfo[uri].title = title;
                modified = true;
            }
            if (_ctiInfo[uri].price != price) {
                _ctiInfo[uri].price = price;
                modified = true;
            }
            if (MetemcyberUtil.isSameStrings(_ctiInfo[uri].operator, operator)
                    == false) {
                _ctiInfo[uri].operator = operator;
                modified = true;
            }
            if (modified == false)
                return;
        }

        emit CtiInfo(
            uri,
            _ctiInfo[uri].tokenId,
            _ctiInfo[uri].owner,
            current_uuid,
            title,
            price,
            operator
        );
    }

    function unregisterCti(string calldata tokenURI) public {
        require(this.validatePurchase(msg.sender), "not permitted");
        string memory uri = MetemcyberUtil.toChecksumAddress(tokenURI);
        require(bytes(_ctiInfo[uri].uuid).length > 0, "not registered");
        require(msg.sender == _ctiInfo[uri].owner, "not owner");

        delete _ctiInfo[uri];
        uint256 index = _ctiIndex[uri];
        delete _tokenList[index];  // just set "", not shrinked.

        emit CtiInfo(uri, 0, address(0), "", "", 0, "");
    }

    function listTokenURIs() public view returns (string[] memory list) {
        // Note: array contains "" which means unregistered.
        return _tokenList;
    }

    function getCtiInfo(
        string calldata tokenURI
    ) public view returns (Cti memory) {
        string memory uri = MetemcyberUtil.toChecksumAddress(tokenURI);
        Cti memory cti = _ctiInfo[uri];
        require(bytes(cti.uuid).length > 0, "no such cti");
        return cti;
    }

    function likeCti(string calldata tokenURI) public{
        require(this.validatePurchase(msg.sender), "not permitted");
        string memory uri = MetemcyberUtil.toChecksumAddress(tokenURI);
        require(bytes(_ctiInfo[uri].uuid).length > 0, "not registered");

         _ctiInfo[uri].likecount.increment();

        emit CtiLiked(
            uri,
            _ctiInfo[uri].likecount.current(),
            msg.sender
        );
    }

    function validatePurchase(address buyer) public view returns(bool) {
        if (address(members) == address(0))  // public mode
            return true;
        if (owner == buyer)  // owner is always available even if not a member
            return true;
        return members.isMember(buyer);
    }
}
