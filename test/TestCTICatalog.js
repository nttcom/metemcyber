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
const {format} = require("util");

contract("Catalog Owner test", async accounts => {
  var catalog;

  it("Owner account should same as tx.origin", async () => {
    catalogowner = accounts[0];
    catalog = await CTICatalog.deployed();
    let owner = await catalog.getOwner();
    assert.equal(owner, catalogowner);
  });

  it("Register Token test", async () => {
    let token = await CTIToken.deployed();
    let balance = await token.balanceOf(catalogowner);

    let tokenURI = token.address;
    let uuid = "19941db5-7f5f-4000-b7b0-cd8c3d5564e8"; //dummy uuid
    let title = "test title";
    let price = 10;
    let operator = "operator@test";
    
    //console.log("Register cti");
    await catalog.registerCti(tokenURI, uuid, title, price, operator);

    let values  = await catalog.listTokenURIs();
    console.log(typeof values);
    assert.equal(values[0], tokenURI, "tokenURI does not exist");

    let cti = await catalog.getCtiInfo(tokenURI);
    //console.log(format("cti ifno: %s", cti));

    assert.equal(cti.uuid, uuid, "uuid mismatch!");
    assert.equal(cti.title, title, "title mismatch!");
    assert.equal(cti.price, price, "price mismatch!");
    assert.equal(cti.operator, operator, "operator mismatch!");
  });
});
