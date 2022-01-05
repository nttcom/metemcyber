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
const { BN, constants, expectEvent, expectRevert, singletons } = require('@openzeppelin/test-helpers');

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



/* Test for Votable */

  const owner = accounts[0];
  const guest = accounts[1];
  var editableToken, uneditableToken;

  it("deploy", async() => {
    editableToken = await CTIToken.new(10, [], true, {from: owner});
  });

  it("editable control", async() => {
    let editable = await editableToken.editable({from: owner});
    assert.equal(editable, true, "unexpected result for editableToken");
    await expectRevert(editableToken.setEditable(false, {from: guest}), "not permitted");

    uneditableToken = await CTIToken.new(10, [], false, {from: owner});
    editable = await uneditableToken.editable({from: owner});
    assert.equal(editable, false, "unexpected result for uneditableToken");
    await uneditableToken.setEditable(true, {from: owner});
    editable = await uneditableToken.editable({from: owner});
    assert.equal(editable, true, "unexpected result for editabled Token");
    await uneditableToken.setEditable(false, {from: owner});
    editable = await uneditableToken.editable({from: owner});
    assert.equal(editable, false, "unexpected result for uneditabled Token");
  });

  it("addCandidates by owner", async() => {
    eList = await editableToken.listCandidates({from: owner});
    uList = await uneditableToken.listCandidates({from: owner});
    assert.equal(eList.length, 0, "unexpected initial candidates for editable");
    assert.equal(uList.length, 0, "unexpected initial candidates for uneditable");

    await editableToken.addCandidates(["alpha1", "alpha2", "alpha3"], {from: owner});
    await uneditableToken.addCandidates(["alpha1", "alpha2", "alpha3"], {from: owner});
    eList = await editableToken.listCandidates({from: owner});
    uList = await uneditableToken.listCandidates({from: owner});
    assert.equal(eList.length, 3, "unexpected candidates after added by owner for editable");
    assert.equal(uList.length, 3, "unexpected candidates after added by owner for uneditable");
    // console.log(eList);
  });

  it("addCandidates by guest", async() => {
    await editableToken.addCandidates(["beta1", "beta2"], {from: guest});
    await expectRevert(uneditableToken.addCandidates(["beta1", "beta2"], {from: guest}),
        "not permitted");
    eList = await editableToken.listCandidates({from: owner});
    uList = await uneditableToken.listCandidates({from: owner});
    assert.equal(eList.length, 5, "unexpected candidates after added by guest for editable");
    assert.equal(uList.length, 3, "unexpected candidates after added by guest for uneditable");
    // console.log(eList);
  });

  it("addCandidates duplicated", async() => {
    await expectRevert(editableToken.addCandidates(["gamma1", "alpha1"], {from: owner}),
        "already added");
  });

  it("addCandidates empty", async() => {
    await expectRevert(editableToken.addCandidates(["delta1", ""], {from: owner}),
        "empty candidate");
  });

  it("removeCandidates by guest", async() => {
    await editableToken.removeCandidates([1, 3], {from: guest});
    await expectRevert(uneditableToken.removeCandidates([1], {from: guest}), "not permitted");
    eList = await editableToken.listCandidates({from: owner});
    uList = await uneditableToken.listCandidates({from: owner});
    assert.equal(eList.length, 3, "unexpected candidates after added by guest for editable");
    assert.equal(uList.length, 3, "unexpected candidates after added by guest for uneditable");
    // console.log(eList);
  });

  it("removeCandidates twice", async() => {
    await expectRevert(editableToken.removeCandidates([1], {from: owner}), "already removed");
  });

  it("vote without token", async() => {
    balance = await editableToken.balanceOf.call(guest);
    assert.equal(balance, 0, "unexpected balance for guest");
    await expectRevert(editableToken.vote(2, 1, {from: guest}),
        "VM Exception while processing transaction: revert ERC777: burn amount exceeds balance -- Reason given: ERC777: burn amount exceeds balance.");
  });

  it("vote with token", async() => {
    await editableToken.send(guest, 7, [], {from: owner});
    balance = await editableToken.balanceOf.call(guest);
    assert.equal(balance, 7, "unexpected balance for guest");
    eList = await editableToken.listCandidates({from: owner});
    assert.equal(eList[2].score, 0, "voted without burning token");

    await editableToken.vote(2, 3, {from: guest});
    eList = await editableToken.listCandidates({from: owner});
    // Note: '1' is removed. then voted '2' is listed as eList[1].
    assert.equal(eList[1].score, 3);
    balance = await editableToken.balanceOf.call(guest);
    assert.equal(balance, 7-3, "amount of burned token mismatch");
  });

  it("vote too much", async() => {
    await expectRevert(editableToken.vote(2, 100, {from: guest}),
        "VM Exception while processing transaction: revert ERC777: burn amount exceeds balance -- Reason given: ERC777: burn amount exceeds balance.");
  });

  it("vote with zero", async() => {
    await expectRevert(editableToken.vote(2, 0, {from: guest}), "invalid amount");
  });

  it("vote to removed candidate", async() => {
    await expectRevert(editableToken.vote(1, 1, {from: guest}), "invalid index");
  });

  it("remove not voted candidate by guest", async() => {
    eList = await editableToken.listCandidates({from: owner});
    // console.log(eList);
    assert.equal(eList.length, 3);
    await editableToken.removeCandidates([4], {from: guest});
    eList = await editableToken.listCandidates({from: owner});
    // console.log(eList);
    assert.equal(eList.length, 2);
  });

  it("remove voted candidate by guest", async() => {
    await expectRevert(editableToken.removeCandidates([2], {from: guest}),
        "not permitted (already voted)");
  });

  it("remove voted candidate by owner", async() => {
    await editableToken.removeCandidates([2], {from: owner});
    eList = await editableToken.listCandidates({from: owner});
    // console.log(eList);
    assert.equal(eList.length, 1)
  });


});
