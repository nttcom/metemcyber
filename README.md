# Metemcyber

Decentralized Cyber Threat Intelligence Refinement Framework.

[Metemcyber User Documentation](https://docs.google.com/document/d/1RL_0hDulTSuogskajhyv--eHGTsOiO6g2WLE4nTned4/edit?usp=sharing)

## Overview

- Cyber Threat Intelligence (MISP Objects) のプログラマブルな流通・共有
- Cyber Threat Intelligence の利活用状況の記録

```
git clone --recursive https://github.com/nttcom/metemcyber
cd metemcyber
geth account new
./metemcyber_ctl.sh pricom init 
./metemcyber_ctl.sh - client -f $YOUR_KEY_FILE -w $WEBHOOK_URL
```

## Requirement

Ubuntu 18.04, 20.04, macOS Catalina で動作を確認しています。

- Docker環境 (Docker-CE等)

## Install

Docker環境をセットアップします。

https://docs.docker.com/install/linux/docker-ce/ubuntu/


次に、ユーザーをdockerグループに所属させます。ユーザがdockerグループに所属したことを `id` コマンドで確認してください。

```
sudo usermod -aG docker $USER
su - $USER
id
```

必要なパッケージをインストールします。
```
sudo add-apt-repository -y ppa:ethereum/ethereum
sudo apt-get update
sudo apt install ethereum jq curl python3-dateutil
```

リポジトリをクローンして、metemcyberのフォルダに移動します。
```
git clone --recursive https://github.com/nttcom/metemcyber.git
cd metemcyber
```

## QuickStart

NTTコミュニケーションズのEnterprise Ethereum "Pricom" へ接続します。

### Metemcyberのセットアップ

Ethereum上で利用する鍵ファイルを作成します
```
geth account new
```

Metemcyber実行環境を初期化します。
```
./metemcyber_ctl.sh pricom init
```

P2P接続にngrokを用いるため、以下サイトにてアカウント作成を実施します。

https://dashboard.ngrok.com/

その後、setupページに従ってngrokをセットアップします。

https://dashboard.ngrok.com/get-started/setup


### Metemcyberの起動

**別画面**でngrokを起動し、インターネット上からのデータ接続を可能にします。
```
./ngrok http 51004
```

ngrokが起動されていることを確認し、Metemcyberのクライアントを起動します。
このとき、先ほど作成した鍵ファイルと、ngrok画面で表示されている通信先を指定してください。

```
./metemcyber_ctl.sh - client -f $YOUR_KEY_FILE -w $YOUR_NGROK_URL
```

**🎉🎉🎉Metemcyberへようこそ！🎉🎉🎉**

### Metemcyberの終了
メニュー画面で 0 を入力するか、Ctrl-C を入力します。

Ctrl-Dを入力すると、いつでもメニュー画面に戻ることができます。

