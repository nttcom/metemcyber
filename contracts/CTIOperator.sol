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

import "@openzeppelin/contracts/token/ERC777/IERC777.sol";
import "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import "@openzeppelin/contracts/utils/introspection/IERC1820Registry.sol";
import "@openzeppelin/contracts/utils/introspection/ERC1820Implementer.sol";
import "./MetemcyberUtil.sol";
import {CTIToken, CTIToken_ContractId} from "./CTIToken.sol";

string constant CTIOperator_ContractId = "CTIOperator.sol:CTIOperator";

contract CTIOperator is IERC777Recipient, ERC1820Implementer {

    event TokensReceivedCalled(
        address from,
        bytes data,
        address token,
        uint256 taskId
    );

    event TaskAccepted(
        address operator,
        uint256 taskId,
        address token
    );

    event TaskFinished(
        address operator,
        uint256 taskId,
        address token
    );

    enum TaskState { Pending, Accepted, Finished, Cancelled }

    struct Task {
        uint256 taskId;
        address token;
        address solver;
        address seeker;
        TaskState state;
    }

    string public constant contractId = CTIOperator_ContractId;
    uint256 public constant contractVersion = 1;

    IERC1820Registry private _erc1820 =
        IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);
    bytes32 constant private _TOKENS_RECIPIENT_INTERFACE_HASH =
        keccak256("ERC777TokensRecipient");

    Task[] private _tasks;
    bytes[] private _userData;

    mapping (address => address[]) private _solvers; // CTI => solvers

    function tokensReceived(
        address /*operator*/,
        address from,
        address /*to*/,
        uint256 /*amount*/,
        bytes calldata userData,
        bytes calldata /*operatorData*/
    ) external override {

        IERC777 token = IERC777(msg.sender);

        // prepare for accepted().
        uint256 taskId = _tasks.length; // zero-based taskId.
        _tasks.push(Task({
                taskId: taskId,
                token: address(token),
                solver: address(0),
                seeker: from,
                state: TaskState.Pending
            })
        );
        _userData.push(userData);
        assert(_tasks.length == taskId + 1);
        assert(_userData.length == taskId + 1);

        emit TokensReceivedCalled(
            from,
            userData,
            address(token),
            taskId
        );
    }

    function reemitPendingTasks(address[] memory tokens) public {
        for (uint i=0; i<_tasks.length; i++) {
            if (_tasks[i].state != TaskState.Pending)
                continue;
            for (uint j=0; j<tokens.length; j++) {
                if (_tasks[i].token == tokens[j]) {
                    emit TokensReceivedCalled(
                        _tasks[i].seeker,
                        _userData[i],
                        _tasks[i].token,
                        _tasks[i].taskId
                    );
                    break;
                }
            }
        }
    }

    function recipientFor(address account) public {
        _registerInterfaceForAddress(
            _TOKENS_RECIPIENT_INTERFACE_HASH, account);

        address self = address(this);
        if (account == self) {
            registerRecipient(self);
        }
    }

    function registerRecipient(address recipient) public {
        _erc1820.setInterfaceImplementer(
            address(this), _TOKENS_RECIPIENT_INTERFACE_HASH, recipient);
    }

    function _isRegistered(
        address token,
        address solver
    ) internal view returns (bool) {
        for (uint i = 0; i < _solvers[token].length; i++) {
            if (_solvers[token][i] == solver)
                return true;
        }
        return false;
    }

    function register(address[] memory tokens) public {
        if (tokens.length == 0)
            return;
        for (uint i = 0; i < tokens.length; i++) {
            require(
                MetemcyberUtil.isSameStrings(
                    CTIToken(tokens[i]).contractId(), CTIToken_ContractId),
                "not a token address"
            );
            if (!_isRegistered(tokens[i], msg.sender)) {
                uint j = 0;
                for (j = 0; j < _solvers[tokens[i]].length; j++) {
                    if (_solvers[tokens[i]][j] == address(0)) {
                        _solvers[tokens[i]][j] = msg.sender;
                        break;
                    }
                }
                if (j == _solvers[tokens[i]].length)
                    _solvers[tokens[i]].push(msg.sender);
            }
        }
    }

    function unregister(address[] memory tokens) public {
        if (tokens.length == 0)
            return;
        for (uint i = 0; i < tokens.length; i++) {
            for (uint j = 0; j < _solvers[tokens[i]].length; j++) {
                if (_solvers[tokens[i]][j] == msg.sender) {
                    delete _solvers[tokens[i]][j];
                    break;
                }
            }
        }
    }

    function checkRegistered(
        address[] memory tokens
    ) public view returns (bool[] memory) {
        bool[] memory result = new bool[](tokens.length);
        for (uint i = 0; i < tokens.length; i++) {
            for (uint j = 0; j < _solvers[tokens[i]].length; j++) {
                if (_solvers[tokens[i]][j] == msg.sender) {
                    result[i] = true;
                    break;
                }
            }
        }
        return result;
    }

    function accepted(uint256 taskId) public {
        require(_tasks.length > taskId,  "Invalid taskId.");
        require(_tasks[taskId].taskId == taskId, "Invalid taskId.");
        require(_tasks[taskId].solver == address(0), "Already accepted.");
        require(
            _isRegistered(_tasks[taskId].token, msg.sender),
            "Not registered."
        );

        _tasks[taskId].solver = msg.sender;
        _tasks[taskId].state = TaskState.Accepted;
        emit TaskAccepted(
            address(this),
            taskId,
            _tasks[taskId].token
        );
    }

    function finish(uint256 taskId, string memory data) public {
        require(_tasks.length > taskId, "Invalid taskId");
        require(_tasks[taskId].solver == msg.sender, "not task's solver");

        // send token back to seeker
        IERC777 token = IERC777(_tasks[taskId].token);
        assert(token.balanceOf(address(this)) > 0);
        _tasks[taskId].state = TaskState.Finished;
        token.send(_tasks[taskId].seeker, 1, bytes(data));
        delete _userData[taskId];

        emit TaskFinished(
            address(this),
            taskId,
            _tasks[taskId].token
        );
    }

    function cancelTask(uint256 taskId) public {
        require(_tasks.length > taskId, "Invalid taskId");
        require(_tasks[taskId].seeker == msg.sender, "Not token sender");
        require(_tasks[taskId].state == TaskState.Pending, "Not pending");

        IERC777 token = IERC777(_tasks[taskId].token);
        assert(token.balanceOf(address(this)) > 0);
        _tasks[taskId].state = TaskState.Cancelled;
        token.send(_tasks[taskId].seeker, 1, "");
        delete _userData[taskId];

        emit TaskFinished(
            address(this),
            taskId,
            _tasks[taskId].token
        );
    }

    function latest() external view returns (Task memory) {
        require(_tasks.length > 0,  "No tasks");
        return _tasks[_tasks.length-1];
    }

    function history(
        address token,
        address seeker,
        uint limit,
        uint offset
    ) external view returns (Task[] memory) {
        require(limit > 0,  "Specify more than 1");
        if (_tasks.length == 0)
            return new Task[](0);

        // Use new keyword to create dynamic length array
        Task[] memory matchTasks = new Task[](limit);
        uint count = 0;

        for (uint i = _tasks.length; i > 0 && count < limit; i--) {
            if ((seeker == address(0) || _tasks[i - 1].seeker == seeker) &&
                    (token == address(0) || _tasks[i - 1].token == token)) {
                if (offset > 0) {
                    offset--;
                    continue;
                }
                matchTasks[count] = _tasks[i - 1];
                count++;
            }
        }
        if (count < limit){
            Task[] memory sliceTasks = new Task[](count);
            for (uint i = 0; i < count; i++) {
                sliceTasks[i] = matchTasks[i];
            }
            return sliceTasks;
        } else {
            return matchTasks;
        }
    }
}
