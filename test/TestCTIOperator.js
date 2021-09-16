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
const { BN, constants, expectEvent, expectRevert, singletons } = require('@openzeppelin/test-helpers');
const { ZERO_ADDRESS } = constants;


contract("CTIOperator", async accounts => {
  const owner = accounts[0];  // token owner
  const solver = accounts[1];  // solver (should be authorized by token owner)
  const anon = accounts[2];  // operator deployer
  const user = accounts[3];  // token user
  var operator;
  var token;
  var taskId;
  const nilHex = web3.utils.asciiToHex("");
  const expectedNilTokens = [].toString();
  var expectedRegisteredTokens;

  it("deploy and recipientFor", async () => {
    operator = await CTIOperator.new({from: anon});
    await operator.recipientFor(operator.address);
  });

  it("register by token owner", async () => {
    token = await CTIToken.new(1, [], false, {from: owner});
    await operator.register([token.address], {from: owner});
    let results = await operator.checkRegistered([token.address], {from: owner});
    assert.equal(results[0], true, "checkRegistered mismatch");
    expectedRegisteredTokens = [token.address].sort().toString();
  });

  it("register by solver", async () => {
    await expectRevert(operator.register([token.address], {from: solver}), "not authorized");
    let results = await operator.checkRegistered([token.address], {from: solver});
    assert.equal(results[0], false, "checkRegistered mismatch");
  });

  it("register by authorized solver", async () => {
    await token.authorizeOperator(solver, {from: owner});
    await operator.register([token.address], {from: solver});
    await token.revokeOperator(solver, {from: owner});
    let results = await operator.checkRegistered([token.address], {from: solver});
    assert.equal(results[0], true, "checkRegistered mismatch");
  });

  it("register not a token", async () => {
    await expectRevert(operator.register([operator.address], {from: owner}), "not a token");
  });

  it("listRegistered", async () => {
    let results = await operator.listRegistered(solver, {from: solver});
    assert.equal(results.sort().toString(), expectedRegisteredTokens, "registered mismatch");
    results = await operator.listRegistered(solver, {from: user});
    assert.equal(results.sort().toString(), expectedRegisteredTokens, "registered by user mismatch");
    results = await operator.listRegistered(user, {from: solver});
    assert.equal(results.sort().toString(), expectedNilTokens, "registered for user mismatch");
  });

  it("unregister by token owner", async () => {
    await operator.unregister([token.address], {from: owner});
    let results = await operator.checkRegistered([token.address], {from: owner});
    assert.equal(results[0], false, "checkRegistered mismatch");
  });

  it("unregister by solver", async () => {
    await operator.unregister([token.address], {from: solver});  // not authorized
    let results = await operator.checkRegistered([token.address], {from: solver});
    assert.equal(results[0], false, "checkRegistered mismatch");
  });

  it("get TokenReceivedCalled event", async () => {
    await token.send(user, 1, nilHex, {from: owner});
    assert.equal(await token.balanceOf(user), 1, "token balance mismatch");
    await token.send(operator.address, 1, nilHex, {from: user});
    assert.equal(await token.balanceOf(user), 0, "token balance mismatch");
    assert.equal(await token.balanceOf(operator.address), 1, "token balance mismatch");
    let events = await operator.getPastEvents('TokensReceivedCalled',
        {fromBlock: 0, toBlock: 'latest', from: solver});
    let task = events[0].returnValues;
    // console.log(task);
    assert.equal(task.taskId, 0, "task.taskId mismatch");
    assert.equal(task.token, token.address, "task.token mismatch");
    assert.equal(task.from, user, "task.seeker mismatch");
    taskId = task.taskId;
  });

  it("accept without register by solver", async () => {
    await expectRevert(operator.accepted(taskId, {from: solver}), "Not registered.");
  });

  it("register and accept by solver", async () => {
    await token.authorizeOperator(solver, {from: owner});
    await operator.register([token.address], {from: solver});
    await token.revokeOperator(solver, {from: owner});
    await expectRevert(operator.accepted(taskId, {from: solver}), "not authorized");
  });

  it("register and accept by authorized solver", async () => {
    await token.authorizeOperator(solver, {from: owner});
    await operator.register([token.address], {from: solver});
    await operator.accepted(taskId, {from: solver});
    let task = await operator.latest({from: solver});
    // console.log(task);
    assert.equal(task.taskId, taskId, "task.taskId mismatch");
    assert.equal(task.token, token.address, "task.token mismatch");
    assert.equal(task.solver, solver, "task.solver mismatch");
    assert.equal(task.seeker, user, "task.seeker mismatch");
    assert.equal(task.state, 1, "task.state mismatch");  // TaskState.Accepted == 1
  });

  it("accept twice", async () => {
    await expectRevert(operator.accepted(taskId, {from: solver}), "Already accepted.");
  });

  it("finish by not solver", async () => {
    await expectRevert(operator.finish(taskId, nilHex, {from: owner}), "not task's solver");
  });

  it("finish by revoked solver", async () => {  // allowed because already accepted
    await token.revokeOperator(solver, {from: owner});
    await operator.finish(taskId, nilHex, {from: solver});
    let task = await operator.latest({from: solver});
    // console.log(task);
    assert.equal(task.taskId, taskId, "task.taskId mismatch");
    assert.equal(task.state, 2, "task.state mismatch");  // TaskState.Finished == 2
  });

  it("sendback finished token", async () => {
    assert.equal(await token.balanceOf(operator.address), 0, "token balance mismatch");
    assert.equal(await token.balanceOf(user), 1, "token balance mismatch");
  });

});
