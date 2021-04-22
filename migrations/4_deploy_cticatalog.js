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

const MetemcyberUtil = artifacts.require("MetemcyberUtil");
const CTICatalog = artifacts.require("CTICatalog");
const { BN, constants, expectEvent, expectRevert, singletons } = require('@openzeppelin/test-helpers');
const { ZERO_ADDRESS } = constants;

module.exports = function (deployer) {
  deployer.deploy(MetemcyberUtil);
  deployer.link(MetemcyberUtil, CTICatalog);
  deployer.deploy(CTICatalog, ZERO_ADDRESS);
};
