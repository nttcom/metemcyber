<div align="center">

[![banner](https://raw.githubusercontent.com/nttcom/metemcyber/main/banner.png)](https://metemcyber.ntt.com)

# Metemcyber

</div>

> Decentralized Cyber Threat Intelligence Kaizen Framework. https://metemcyber.ntt.com


[![CI](https://github.com/nttcom/metemcyber/actions/workflows/main.yml/badge.svg)](https://github.com/nttcom/metemcyber/actions/workflows/main.yml)
[![Documentation Status](https://readthedocs.org/projects/metemcyber/badge/?version=latest)](https://metemcyber.readthedocs.io/ja/latest/?badge=latest)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/nttcom/metemcyber)
[![GitHub commit activity](https://img.shields.io/badge/discussions-welcome!-success)](https://github.com/nttcom/metemcyber/discussions)
[![Twitter](https://img.shields.io/twitter/follow/metemcyber?label=Follow&style=social)](https://twitter.com/metemcyber)
<!-- ![GitHub Release](https://img.shields.io/github/v/release/nttcom/metemcyber.svg?style=flat) -->


## 💡 Overview

Metemcyber™ enables security collaboration and assessment all the across organization through the intelligence cycle successful.

## ✨ Features

**Anyone can make the intelligence cycle successful.**

- Content-oriented Workflow
- Fault-tolerant Collaboration
- Disclosure Control of CTIs
- Measuring the Cost-Effectiveness of CTIs
- Transparency for Trust
    - Monitoring the trading activity of CTIs
    - Unlocking achievements based on your contribution.
- MISP friendly

## 🚅 QuickStart

This exercise will be performed on the testnet environment.

```
pip install $PACKAGE_NAME[cli]
```


### 🔑 Create a new account

Create a new account if no keyfile available:

```
metemctl account create
```

Display your account details you are currently using:

```
metemctl account show
```

> ⚠️ **You must agree to [the terms of service](https://forms.office.com/Pages/ResponsePage.aspx?id=Mu8pprpnpkeOs-xDk1ZE_FdfnH75qvpDtqTkNo9NCzRUN1hRM1lIVVZCTUU3V1VJVjhFWEtQSDFMNy4u).** This is a experimental project on the enterprise ethereum of NTT Communications. **You will get a promo code if you agree to this terms.**

Get a promo code via email, and airdrop yourself some ETH to get started:

```
metemctl account airdrop $PROMOTE_CODE_IN_THE_CONFIRMATION_MAIL
```

### 🛒 Collect CTIs
> ⚠️ **You need an account to use [ngrok](https://dashboard.ngrok.com/).** [Setup the ngrok](https://dashboard.ngrok.com/get-started/setup) and place the ngrok executable in Application directory

Open the application directory and place the ngrok executable:
```
metemctl open-app-dir
```

Search for the CTI token you want to buy (e.g. OSINT)
```
metemctl ix search 'OSINT'
```

Enter the index number of the CTI token to be purchased. (Also CTI token address is acceptable)
```
metemctl ix buy $INDEX_OR_ADDRESS
```
Use CTI token to receive the MISP object on your public URL of the ngrok.
```
metemctl ix use $INDEX_OR_ADDRESS --ngrok
```

## ♻️ Run the Intelligence Cycle

In this section, you will run the intelligence cycle using the exercise *ir-exercise* for Incident Response.

### 🤖 Create a new workflow
```
metemctl new　--starter=ir-exercise
```

### 📝 Summarize the data analysis process

Get data for the exercise *ir-exercise*:
```
metemctl ix search '[ir-exercise]'
```

```
metemctl ix buy $INDEX_OR_ADDRESS
```

```
metemctl ix use $INDEX_OR_ADDRESS --ngrok

```

> ⚠️ In the production, you need to put together a workflow of what you have tried to analyze. By summarizing the process of data analysis, we will be able to objectively judge the usefulness of your analysis methods.

Run the ir-exercise workflow:

```
metemctl run 
```

Check the contents of your CTI product and the workflow:

```
metemctl check --viz
```

### 🚀 Disseminate your CTI products to everyone:

```
metemctl publish
```

🎉🎉🎉 Welcome to Metemcyber, Dear Awesome CTI Analyst!!!  🎉🎉🎉


## 📖 Documentation

For more information see the [documentation](https://metemcyber.readthedocs.io/).

## ⚖️ LICENSE
```
Copyright 2020 NTT Communications Corporation

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

