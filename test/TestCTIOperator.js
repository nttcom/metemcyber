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

const CTIOperator = artifacts.require("CTIOperator");
const CTIToken = artifacts.require("CTIToken");
const {format} = require("util");

contract("CTIOperator", async accounts => {
  it("register and accepted test", async () => {
    let operator = await CTIOperator.deployed();
    let token = await CTIToken.deployed();

    // set ERC777 recipient
    await operator.recipientFor(operator.address);

    //await operator.register(token, {from: accounts[1]});
    await operator.register([token.address], {from: accounts[1]});

    // Send Token to operator
    await token.send(operator.address, 1, web3.utils.asciiToHex(""));

    // Get Event
    let events = await operator.getPastEvents('TokensReceivedCalled', {fromBlock: 0, toBlock: 'latest'});
    //console.log(format("Received Events: %o", events));

    let taskId = events[0].returnValues.taskId;
    //console.log(format("taskId: %d", taskId));

    let tx_receipt = await operator.accepted(taskId, {from: accounts[1]});
    //console.log(format("tx_receipt: %o", tx_receipt));
    assert.equal(tx_receipt.receipt.status, true);

    let registereds = await operator.listRegistered(accounts[1]);
    assert.equal(registereds.sort().toString() == [token.address].sort().toString(), true);
  });
});
