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

import {MetemcyberUtil as MU} from "./MetemcyberUtil.sol";

contract Votable {

    struct Candidate {
        uint256 index;
        uint256 score;
        string desc;
    }

    bool public editable;  // editable by not a token publisher
    address private _vote_controller;
    uint256 private _num_actives;  // num active candidates
    uint256 private _max_index;  // tail of _candidates -- lowest non valid index
    mapping(uint256 => Candidate) private _candidates;

    constructor(bool anyoneEditable) {
        _vote_controller = msg.sender;
        editable = anyoneEditable;
    }

    function setEditable(bool anyoneEditable) public {
        require(_vote_controller == msg.sender, "not permitted");
        editable = anyoneEditable;
    }

    function addCandidates(string[] memory new_candidates) public {
        require(editable || _vote_controller == msg.sender, "not permitted");
        for (uint idx = 0; idx < new_candidates.length; idx++) {
            require(bytes(new_candidates[idx]).length > 0, "empty candidate");
            for (uint x = 0; x < _max_index; x++)
                if (MU.isSameStrings(new_candidates[idx], _candidates[x].desc))
                    revert("already added");
            _candidates[_max_index].index = _max_index;
            _candidates[_max_index].desc = new_candidates[idx];
            _max_index++;
            _num_actives++;
        }
    }

    function removeCandidates(uint256[] memory indexes) public {
        require(editable || _vote_controller == msg.sender, "not permitted");
        for (uint idx = 0; idx < indexes.length; idx++) {
            require(indexes[idx] < _max_index, "invalid index");
            if (bytes(_candidates[indexes[idx]].desc).length == 0)
                revert("already removed");
            if (_candidates[indexes[idx]].score > 0 && _vote_controller != msg.sender)
                revert("not permitted (already voted)");
            delete _candidates[indexes[idx]];
            _num_actives--;
        }
    }

    function listCandidates() public view returns(Candidate[] memory) {
        Candidate[] memory ret = new Candidate[](_num_actives);
        uint x = 0;
        for (uint idx = 0; idx < _max_index; idx++) {
            if (bytes(_candidates[idx].desc).length == 0)
                continue;
            ret[x] = Candidate({
                index: _candidates[idx].index,
                score: _candidates[idx].score,
                desc: _candidates[idx].desc});
            x++;
        }
        return ret;
    }

    function vote(uint256 idx, uint256 amount) public virtual {
        require(bytes(_candidates[idx].desc).length > 0, "invalid index");
        require(amount > 0, "invalid amount");
        _candidates[idx].score += amount;
        /* amount of something should be reduced in sub contract. */
    }
}
