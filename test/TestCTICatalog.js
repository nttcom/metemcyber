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

const CTICatalog = artifacts.require("CTICatalog");
const CTIToken = artifacts.require("CTIToken");
const AddressGroup = artifacts.require("AddressGroup");
const {format} = require("util");
const { BN, constants, expectEvent, expectRevert, singletons } = require('@openzeppelin/test-helpers');
const { ZERO_ADDRESS } = constants;


contract("CTICatalog", async accounts => {
  var catalog;
  var members;
  const owner = accounts[0];
  const guest = accounts[1];

  it("Owner account should same as tx.origin", async () => {
    catalog = await CTICatalog.deployed();
    let tmp = await catalog.owner();
    assert.equal(owner, tmp);
  });

  it("Register Token test", async () => {
    let token = await CTIToken.deployed();
    let balance = await token.balanceOf(owner);

    let tokenURI = token.address;
    let uuid = "19941db5-7f5f-4000-b7b0-cd8c3d5564e8"; //dummy uuid
    let title = "test title";
    let price = 10;
    let operator = "operator@test";
    
    //console.log("Register cti");
    await catalog.registerCti(tokenURI, uuid, title, price, operator);

    let values  = await catalog.listTokenURIs();
    //console.log(typeof values);
    assert.equal(values[0], tokenURI, "tokenURI does not exist");

    let cti = await catalog.getCtiInfo(tokenURI);
    //console.log(format("cti ifno: %s", cti));

    assert.equal(cti.uuid, uuid, "uuid mismatch!");
    assert.equal(cti.title, title, "title mismatch!");
    assert.equal(cti.price, price, "price mismatch!");
    assert.equal(cti.operator, operator, "operator mismatch!");
  });


  it("deploy without members", async () => {
    catalog = await CTICatalog.new(ZERO_ADDRESS, {from: owner});
    assert.notEqual(ZERO_ADDRESS, catalog.address);
    assert.equal(true, await catalog.validatePurchase(owner));
    assert.equal(true, await catalog.validatePurchase(guest));
  });

  it("set members (switch to private)", async () => {
    members = await AddressGroup.new({from: owner});
    await catalog.setMembers(members.address);
    assert.equal(true, await catalog.validatePurchase(owner));
    assert.equal(false, await catalog.validatePurchase(guest));
  });

  it("authorize guest", async () => {
    await members.add(guest);
    assert.equal(true, await catalog.validatePurchase(owner));
    assert.equal(true, await catalog.validatePurchase(guest));
  });

  it("revoke guest", async () => {
    await members.remove(guest);
    assert.equal(true, await catalog.validatePurchase(owner));
    assert.equal(false, await catalog.validatePurchase(guest));
  });

  it("unset address group (switch to public)", async () => {
    await catalog.setMembers(ZERO_ADDRESS);
    assert.equal(true, await catalog.validatePurchase(owner));
    assert.equal(true, await catalog.validatePurchase(guest));
  });

});
