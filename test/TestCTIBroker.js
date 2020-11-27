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

const CTIBroker = artifacts.require("CTIBroker");
const CTICatalog = artifacts.require("CTICatalog");
const CTIToken = artifacts.require("CTIToken");
const BigNumber = require("bignumber.js");
const {format} = require("util");

const PTS_RATE = 10**18; // 1pts = PTS_RATE wei

contract("CTIBroker", (accounts) => {

  var broker;
  var catalog;
  var token;
  const owner = accounts[0];
  const buyer = accounts[1];
  const observer = accounts[2];
  var iBalanceOwner;
  var iBalanceBuyer;
  var iTokenBalanceOwner;
  var iTokenBalanceBuyer;
  var iTokenBalanceBroker;
  var iTokenBalanceCatalog;
  var iTokenAmount;
  const tokenPrice10 = 10; // in Ether
  const tokenPrice20 = 20;
  const num_consign = 7;
  const num_takeback = 2;

  it('initial CTIBroker', async() => {
    broker = await CTIBroker.deployed();
    catalog = await CTICatalog.deployed();
    token = await CTIToken.deployed();

    const iBalanceBroker = await web3.eth.getBalance(broker.address);
    assert.equal(iBalanceBroker, 0, "init balance of broker is NOT zero");
    iBalanceOwner = BigNumber(await web3.eth.getBalance(owner));
    iBalanceBuyer = BigNumber(await web3.eth.getBalance(buyer));

    iTokenBalanceOwner = await token.balanceOf.call(owner);
    iTokenBalanceBuyer = await token.balanceOf.call(buyer);
    iTokenBalanceBroker = await token.balanceOf.call(broker.address);
    iTokenBalanceCatalog = await token.balanceOf.call(catalog.address);
    iTokenAmounts = await broker.getAmounts(catalog.address, [token.address]);

    assert.equal(iTokenBalanceOwner, 10, "initial token of owner mismatch!");
    assert.equal(iTokenBalanceBuyer, 0, "initial token of buyer mismatch!");
    assert.equal(iTokenBalanceBroker, 0, "initial token of broker mismatch!");
    assert.equal(iTokenBalanceCatalog, 0, "initial token of catalog mismatch!");
    assert.equal(iTokenAmounts[0], 0, "initial token amount mismatch!");
  });

  it('consign token to broker', async() => {
    const uuid = "19941db5-7f5f-4000-b7b0-cd8c3d5564e8";
    const title = "test title";
    await catalog.registerCti(token.address, uuid, title, tokenPrice10, "");
    await catalog.publishCti(owner, token.address);

    await token.authorizeOperator(broker.address);
    await broker.consignToken(catalog.address, token.address, num_consign);

    const cTokenBalanceOwner = await token.balanceOf.call(owner);
    const cTokenBalanceBuyer = await token.balanceOf.call(buyer);
    const cTokenBalanceBroker = await token.balanceOf.call(broker.address);
    const cTokenBalanceCatalog = await token.balanceOf.call(catalog.address);
    const cTokenAmounts = await broker.getAmounts(catalog.address, [token.address]);

    assert.equal(cTokenBalanceOwner, iTokenBalanceOwner - num_consign, "owner token mismatch!")
    assert.equal(cTokenBalanceBuyer, 0, "buyer token mismatch!");
    assert.equal(cTokenBalanceBroker, num_consign, "broker token mismatch!");
    assert.equal(cTokenBalanceCatalog, 0, "catalog token mismatch!");
    assert.equal(cTokenAmounts[0], num_consign, "consigned token amount mismatch!");
  });

  it('buy token from broker with just price', async() => {

    await broker.buyToken(catalog.address, token.address, false,
        {from: buyer, value: tokenPrice10*PTS_RATE});

    const bTokenBalanceOwner = await token.balanceOf.call(owner);
    const bTokenBalanceBuyer = await token.balanceOf.call(buyer);
    const bTokenBalanceBroker = await token.balanceOf.call(broker.address);
    const bTokenBalanceCatalog = await token.balanceOf.call(catalog.address);
    const bTokenAmounts = await broker.getAmounts(catalog.address, [token.address]);
    const bBalanceOwner = BigNumber(await web3.eth.getBalance(owner));
    const bBalanceBuyer = BigNumber(await web3.eth.getBalance(buyer));

    assert.equal(bTokenBalanceOwner, iTokenBalanceOwner - num_consign, "owner token mismatch!");
    assert.equal(bTokenBalanceBuyer, 1, "buyer token mismatch!");
    assert.equal(bTokenBalanceBroker, num_consign - 1, "broker token mismatch!");
    assert.equal(bTokenBalanceCatalog, 0, "catalog token mismatch!");
    assert.equal(bTokenAmounts[0], num_consign - 1, "left token amount mismatch!");

    let diff = bBalanceOwner.minus(iBalanceOwner);
    assert.equal(diff <= tokenPrice10*PTS_RATE &&
                diff > tokenPrice10*PTS_RATE - 1*10**18, // consider gas
        true, "owner did not receive enough ETHER");
    diff = iBalanceBuyer.minus(bBalanceBuyer);
    assert.equal(diff >= tokenPrice10*PTS_RATE &&
                diff < tokenPrice10*PTS_RATE + 1*10**18, //consider gas
        true, "buyer did not pay enough ETHER");
  });

  it('buy token from broker with too much price', async() => {

    await broker.buyToken(catalog.address, token.address, true, // allow_cheaper
        {from: buyer, value: tokenPrice20*PTS_RATE});

    const bTokenBalanceOwner = await token.balanceOf.call(owner);
    const bTokenBalanceBuyer = await token.balanceOf.call(buyer);
    const bTokenBalanceBroker = await token.balanceOf.call(broker.address);
    const bTokenBalanceCatalog = await token.balanceOf.call(catalog.address);
    const bTokenAmounts = await broker.getAmounts(catalog.address, [token.address]);
    const bBalanceOwner = BigNumber(await web3.eth.getBalance(owner));
    const bBalanceBuyer = BigNumber(await web3.eth.getBalance(buyer));

    assert.equal(bTokenBalanceOwner, iTokenBalanceOwner - num_consign, "owner token mismatch!");
    assert.equal(bTokenBalanceBuyer, 2, "buyer token mismatch!");
    assert.equal(bTokenBalanceBroker, num_consign - 2, "broker token mismatch!");
    assert.equal(bTokenBalanceCatalog, 0, "catalog token mismatch!");
    assert.equal(bTokenAmounts[0], num_consign - 2, "left token amount mismatch!");

    let diff = bBalanceOwner.minus(iBalanceOwner);
    assert.equal(diff <= 2 * tokenPrice10*PTS_RATE &&
                diff > 2 * tokenPrice10*PTS_RATE - 1*10**18, // consider gas
        true, "owner did not receive enough ETHER");
    diff = iBalanceBuyer.minus(bBalanceBuyer);
    assert.equal(diff >= 2 * tokenPrice10*PTS_RATE, true, "buyer did not pay enough ETHER");
    assert.equal(diff < 2 * tokenPrice10*PTS_RATE + 1*10**18, //consider gas
        true, "buyer did not receive change");
  });

  it('takeback token from broker', async() => {

    await broker.takebackToken(catalog.address, token.address, num_takeback);

    const bTokenBalanceOwner = await token.balanceOf.call(owner);
    const bTokenBalanceBuyer = await token.balanceOf.call(buyer);
    const bTokenBalanceBroker = await token.balanceOf.call(broker.address);
    const bTokenBalanceCatalog = await token.balanceOf.call(catalog.address);

    assert.equal(bTokenBalanceOwner, iTokenBalanceOwner - num_consign + num_takeback,
        "owner cannot takeback token");
    assert.equal(bTokenBalanceBuyer, 2, "buyer token mismatch!");
    assert.equal(bTokenBalanceBroker, num_consign - 2 - num_takeback, "broker token mismatch!");
    assert.equal(bTokenBalanceCatalog, 0, "catalog token mismatch!");
  });
});
