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

const CTIToken = artifacts.require("CTIToken");
const {format} = require("util");

contract("CTIToken", (accounts) => {

  var token;
  const initSupply = 10; // see migrations/*_deploy_ctitoken.js
  const send_amount = 1;

  it('initial balance of CTIToken', async() => {
    token = await CTIToken.deployed();
    const iBalanceOwner = await token.balanceOf.call(accounts[0]);
    const iBalanceSomeone = await token.balanceOf.call(accounts[1]);

    //console.log(format("initial balances: owner: %s, someone: %s", iBalanceOwner, iBalanceSomeone));
    assert.equal(iBalanceOwner, initSupply, "init balance of owner is NOT expected");
    assert.equal(iBalanceSomeone, 0, "init balance of someone is NOT expected");
  });

  it('send token to someone', async() => {
    const tx = await token.send(accounts[1], send_amount, []);
    //console.log(tx);
    assert.equal(tx.receipt.status, true, "send CTIToken failed");
  });

  it("result balance of CTIToken", async() => {
    const rBalanceOwner = await token.balanceOf(accounts[0]);
    const rBalanceSomeone = await token.balanceOf(accounts[1]);

    //console.log(format("result balances: owner: %s, someone: %s", rBalanceOwner, rBalanceSomeone));
    assert.equal(rBalanceOwner, initSupply - send_amount, "result balance of owner is NOT expected");
    assert.equal(rBalanceSomeone, send_amount, "result balance of someone is NOT expected");
  });

});
