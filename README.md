<div align="center">

[![banner](https://raw.githubusercontent.com/nttcom/metemcyber/main/images/banner.png)](https://www.metemcyber.ntt.com)

# Metemcyber

</div>

> Decentralized Cyber Threat Intelligence Kaizen Framework. https://www.metemcyber.ntt.com

[![CI](https://github.com/nttcom/metemcyber/actions/workflows/main.yml/badge.svg)](https://github.com/nttcom/metemcyber/actions/workflows/main.yml)
[![Documentation Status](https://readthedocs.org/projects/metemcyber/badge/?version=latest)](https://metemcyber.readthedocs.io/ja/latest/?badge=latest)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/nttcom/metemcyber)
[![GitHub commit activity](https://img.shields.io/badge/discussions-welcome!-success)](https://github.com/nttcom/metemcyber/discussions)
[![Twitter](https://img.shields.io/twitter/follow/metemcyber?label=Follow&style=social)](https://twitter.com/metemcyber)
<!-- ![GitHub Release](https://img.shields.io/github/v/release/nttcom/metemcyber.svg?style=flat) -->

**Pricom Mainnet (rpc.metemcyber.ntt.com)**
| Contract Name | Address |
| ---- | ---- |
| CTICatalog | 0xBcb4b84cdaB65C6e6Efe1697CC41a46D0AEaCA61 |
| CTIBroker | 0xC1814B834E1be7DeE7611fD5F747535369B8683e |
| CTIOperator | 0x35b3fbeABB802E9477b17a63073ABe874A386E25 |
| metemcyber_util</br>(placeholder) | 0x0e5EECFF51a3ab2221fF6bBd240B20E8933ff28A</br>\_\_$47ceb01e1c551398bb2e8f2c8232f40551$\_\_ |

## 💡 Overview

Metemcyber™ enables security collaboration and assessment all across the organization through the [intelligence cycle](https://en.wikipedia.org/wiki/Intelligence_cycle).

- 📖 [**Metemcyber User Documentation**](https://metemcyber.readthedocs.io/)

## ✨ Features

**Anyone can make a successful intelligence cycle.**

- Content-oriented Workflow
- Comparable Data Analysis Process
- Fault-tolerant Collaboration
- Disclosure Control of CTIs
- Measuring the Cost-Effectiveness of CTIs
- Transparency for Trust
    - Monitoring the trading activity of CTIs
    - Unlocking achievements based on your contribution.
- MISP-friendly 🤗

## 🚅 QuickStart

This exercise will be performed on the test environment.

```sh
apt install build-essential python3-dev
pip install -U pip
pip install -U 'metemcyber[cli]'
```

Check the current configuration:

```sh
metemctl config show
```

### 🔑 Create a new account

Create a new account if no keyfile available:

```sh
metemctl account create
```

Display your account details you are currently using:

```sh
metemctl account show
```

> ⚠️ **You must agree to [the terms of service](https://forms.office.com/Pages/ResponsePage.aspx?id=Mu8pprpnpkeOs-xDk1ZE_FdfnH75qvpDtqTkNo9NCzRUN1hRM1lIVVZCTUU3V1VJVjhFWEtQSDFMNy4u).** This is an experimental project on the enterprise ethereum of NTT Communications. **You will get a promo code if you agree to these terms.**

Get a promo code via email, and airdrop yourself some ETH to get started:

```sh
metemctl account airdrop $PROMOTE_CODE_IN_THE_CONFIRMATION_MAIL
```

### 🛒 Collect CTIs
Search for the CTI token you want to buy (e.g. OSINT)
```sh
metemctl ix search 'OSINT'
```

Enter the index number of the CTI token to be purchased. The CTI token address can also be accepted.

```sh
metemctl ix buy $TOKEN_INDEX_OR_ADDRESS
```

> ⚠️ **You need an account to use [ngrok](https://dashboard.ngrok.com/).** [Setup a local ngrok environment](https://dashboard.ngrok.com/get-started/setup).
>Download [ngrok](https://dashboard.ngrok.com/) and extract it.
>Open the application directory to **put the ngrok executable file there**:
>```sh
>metemctl open-app-dir
>```
>```sh
>$ ls "$(metemctl open-app-dir --print-only)"
>external-links.json             metemctl.ini                    ngrok                           ...
>```
>**Ngrok need to connect your ngrok account.** Make sure the ngrok *authtoken* exists after [ngrok setup](https://dashboard.ngrok.com/get-started/setup):
>```sh
>cat ~/.ngrok2/ngrok.yml
>```
>Start a daemon to receive data using ngrok:
>```sh
>metemctl seeker start --ngrok
>metemctl seeker status
>```

Use CTI token to receive the MISP object on your public URL of the ngrok.

```sh
metemctl ix use $TOKEN_INDEX_OR_ADDRESS
```

## ♻️ Run the Intelligence Cycle

In this section, you will run the intelligence cycle using the exercise *ir-exercise* for Incident Response.

> ⚠️ **You need to enable the test catalog as primary catalog**.
>Enable the test catalog & Disable the production catalog:
>```sh
>metemctl ix catalog enable 0x168DD95472cEaF5c28447C8b07A593e205E92A12 # test
>metemctl ix catalog disable 0xBcb4b84cdaB65C6e6Efe1697CC41a46D0AEaCA61 # production
>```
>Check your catalog settings:
>```sh
>$ metemctl ix catalog show
>Catalogs *:active
>  *1 0x168DD95472cEaF5c28447C8b07A593e205E92A12 # test
>   2 0xBcb4b84cdaB65C6e6Efe1697CC41a46D0AEaCA61 # production
>```

### 🤖 Create a new workflow

Metemcyber can be used not only for CTI dissemination but also CTI creation.

```sh
metemctl new　--starter=ir-exercise
```

Implement the analysis process into your workflow by selecting the event ID (In many cases, the same as the UUID of MISP object), the category of CTI (Fraud, Incident Response, Risk Analysis, Security Operations, Security Leadership, Vulnerability Management), and the content(IOCs, TTPs, etc.) you want to include in the CTI.

This is an important piece of evidence to check the "Direction" step in the intelligence cycle.

```sh
Select Intelligence Category (Fraud, IR, RA, SecOps, SecLead, Vuln) [IR]:
Input a new event_id(UUID) [70be8ba5-fa7f-4b8e-aa04-dc76e0fa8c42]:
0: IOC
1: TTP
2: Workflow
Choose contents to be include [0,1]:
================================================================
Event ID: 70be8ba5-fa7f-4b8e-aa04-dc76e0fa8c42
Category: Incident Response
Contents: ['TTPs', 'IOCs']
================================================================
Are you sure you want to create it? [y/N]:
```

### 📝 Summarize the data analysis process

> ⚠️ **Make sure Seeker is running** to receive the data.
>
>```sh
>metemctl seeker status
>```

You need to use [Kedro](https://github.com/quantumblacklabs/kedro) to summarize your data analysis process into a workflow.

In practice, it is difficult to clearly separate the steps of "Collection", "Processing" and "Analysis" in the intelligence cycle, which makes the data analysis process look complicated.

Please keep the following two points to make the data analysis process more maintainable.

- Using the Kedro pipeline to describe *Analysis Strategy*
- Using the Kedro nodes to describe *Analysis Method*

These are important pieces of evidence to check the "Processing" and "Analysis" step in the intelligence cycle.

**For the success of the intelligence cycle, we are more focused on evaluating the data analysis process than on automating the CTI consumption process.**

Get data for the exercise *ir-exercise*:
```sh
metemctl ix search '[ir-exercise]'
metemctl ix buy $TOKEN_INDEX_OR_ADDRESS
metemctl ix use $TOKEN_INDEX_OR_ADDRESS
metemctl ix extract $TOKEN_INDEX_OR_ADDRESS
```

Run the ir-exercise workflow:

```sh
metemctl run --setup
```

Check the contents of your CTI product and the workflow:

```sh
metemctl check --viz
```

The `--viz` option allows you to visualize your data analysis process described by the workflow. (the same as `kedro viz`)

![banner](https://raw.githubusercontent.com/nttcom/metemcyber/main/images/tutorial_kedro_viz.png)

### 🚀 Disseminate your CTI products to everyone:
> ⚠️ ***Solver* must be running** to send the data to token holders.
>
>```sh
>metemctl solver start --enable
>```
>MISP objects can be distributed when Solver is working properly.
>```sh
>$ metemctl solver status
>Solver running with operator you configured(0xe889b84a209719B8f0272376dB49946DbD177aE6).
>```

```sh
metemctl publish
```

🎉🎉🎉 Welcome to Metemcyber! 🎉🎉🎉


## 📖 Documentation

For more information see the [documentation](https://metemcyber.readthedocs.io/).

## ⚖️ LICENSE
```
Copyright 2021 NTT Communications Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

