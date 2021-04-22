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

const AddressGroup = artifacts.require("AddressGroup");
const { BN, constants, expectEvent, expectRevert, singletons } = require('@openzeppelin/test-helpers');
const { ZERO_ADDRESS } = constants;


contract("AddressGroup", async accounts => {
  var addressgroup;
  const owner = accounts[0];
  const guest = accounts[1];

  it("deploy new", async () => {
    addressgroup = await AddressGroup.new({from: owner});
    // console.log(addressgroup.address);
    assert.notEqual(ZERO_ADDRESS, addressgroup.address);
    assert.equal(owner, await addressgroup.owner());
  });

  it("owner is a member", async () => {
    assert.equal(true, await addressgroup.isMember(owner));
  });

  it("guest is not a member", async () => {
    assert.equal(false, await addressgroup.isMember(guest));
  });

  it("authorize guest", async () => {
    addressgroup.add(guest);
    assert.equal(true, await addressgroup.isMember(guest));
  });

  it("protected modification", async () => {
    await expectRevert(addressgroup.add(accounts[2], {from: guest}), "not owner");
  });

  it("filling sparse", async () => {
    addressgroup.add(accounts[2]);
    addressgroup.add(accounts[3]);
    addressgroup.remove(accounts[2]);  // sparse made
    // console.log(await addressgroup.listMembers());
    addressgroup.add(accounts[4]);  // sparse may be filled
    members = await addressgroup.listMembers();
    // console.log(members);
    assert.equal(4, members.length);
  });

  it("revoke guest", async () => {
    addressgroup.remove(guest);
    assert.equal(false, await addressgroup.isMember(guest));
  });

  it("unremovable owner", async () => {
    await expectRevert(addressgroup.remove(owner), "not permitted");
  });

  it("clear", async () => {
    addressgroup.clear();
    assert.equal(true, await addressgroup.isMember(owner));  // owner is still a member
    members = await addressgroup.listMembers();
    // console.log(members);
    assert.equal(1, members.length);
  });

});
