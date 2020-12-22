Metemcyberクライアントのセットアップ
====================================

本ページでは、MetemcyberのInstall方法について解説いたします。


Requirment
----------
* Docker環境 (Docker-CE等)
* `jq <https://stedolan.github.io/jq/>`_ (設定ファイルの解析時に必要)
* Python 3.8+
* `go-ethereum <https://github.com/ethereum/go-ethereum>`__ (鍵作成時に必要)


Metemcyberのセットアップ
------------------------

    .. code-block:: bash

        git clone https://github.com/nttcom/metemcyber.git
        cd metemcyber


ブロックチェーン接続のための鍵作成
----------------------------------
| `go-ethereum <https://github.com/ethereum/go-ethereum>`__ を使用し、鍵を作成します。
| インストール方法は `公式ページ <https://geth.ethereum.org/docs/install-and-build/installing-geth#install-on-ubuntu-via-ppas>`_ を参考に行います。
| ubuntuだと apt コマンドでインストール可能になっています。

    .. code-block:: bash

        sudo add-apt-repository -y ppa:ethereum/ethereum
        sudo apt-get update
        sudo apt-get install ethereum

| 以下のコマンドを実行すると、Ethereumの鍵が作成されます。
| 作成した鍵は、  `~/.ethereum/keystore/[time]--[address]`　に保存されます。

    .. code-block:: bash

        geth account new

ブロックチェーン接続のための設定ファイルの準備
----------------------------------------------
| Ethereumに接続するための設定ファイルを準備します。
| Pricom, ganache などのProviderごとにworkspaceが用意されています。ganacheなどはローカルでのテスト実行のためのworkspaceとなるため、基本的には操作する必要がありません。
| Metemcyber共通のブロックチェーンにアクセスする場合、pricom用のworkspace “workspace.pricom/” に各種設定ファイルを格納します。

environments
~~~~~~~~~~~~~
| 使用するブロックチェーン基盤にMetemcyberクライアントからアクセスするために、workspaceごとの設定ファイルが “workspace.XXXX/environments” に配置されております。
| Metemcyberの環境に接続する際は、workspace.pricom/environments に配置された設定ファイルを利用します。
| workspaceごとの設定ファイルが workspace.[workspace名]/environments に生成されるため、基本的にユーザが操作する必要はありません。

    .. code-block::
        :caption: workspace.pricom/environments

        ## static params around network (out of our control)
        DOCKER_NETWORK=memcyber-pricom
        PROVIDER_HOST=rpc.metemcyber.ntt.com
        PROVIDER_FROM_LOCAL=https://${PROVIDER_HOST}

config
~~~~~~~
| Metemcyber上でCTIを収集するためには、配布されているCTIのリストを保持しているコントラクト (カタログコントラクト) などを参照する必要があります。
| カタログコントラクトのアドレスなど、Metemcyber を利用するのに必要なアドレスが　workspace.pricom/config.ini から参照されます。このファイルはデフォルトで設定されており、基本的にユーザが操作する必要はありません。

    .. code-block::
        :caption: workspace.pricom/config.ini

        [catalog]
        address = 0x2174f4D4f9e0900838dFF911eC27f892aE681365

        [broker]
        address = 0x05F58Fa2eb18F0AD386daAfE7BDC189af3299945

        [operator]
        address = 0xaFA074f0Df765F2D65e5Ba9354DF11FA21C32026
        owner = 0x97aa90C5D1CAA592707CC26f6B8BEFe56b5e025d
        solver_pluginfile =

        [memcyber_util]
        address = 0x40Ce47d31990703C5Aa8C9D889b7eBefBCD47829
        placeholder = __$d155a977877e3237ef3c963856ee3253bb$__


metemcyber.settings
~~~~~~~~~~~~~~~~~~~~
| metemcyber の実証実験においては、クライアント間でCTIの実ファイルを共有するために、Google Cloud Platoform (GCP) を利用します。GCPにアクセスするための情報を metemcyber.settings に記載します。
| 実証実験の利用規約に同意したときに表示されたアクセストークンを “FUNCTIONS_TOKEN” に入力します。
| 例として、アクセストークンが 「abcdefgh」の場合は以下のように入力します。

    .. code-block::
        :caption: metemcyber.settings

        FUNCTIONS_URL=https://exchange.prod.metemcyber.ntt.com
        FUNCTIONS_TOKEN=abcdefgh

セットアップコマンドの実行
~~~~~~~~~~~~~~~~~~~~~~~~~~
| 本稿では、Metemcyber クライアントをMetemcyber 環境のブロックチェーン(Pricom)に接続するための、セットアップコマンドの利用方法について説明します。
| クライアントのセットアップ、起動などには、Metemcyber クライアントプログラムの memcyber_ctl.sh を使用します。
| クライアントのセットアップは以下のコマンドを実行します

    .. code-block:: bash

        ./memcyber_ctl.sh pricom init

| 上記コマンドで、“workspace/” ディレクトリから、pricom 用のworkspace  である “workspace.pricom/” へのシンボリックリンクが設定されます。
| Metemcyber クライアントプログラムは “workspace” のディレクトリ内の設定ファイルを参照してブロックチェーンに接続します。 
| `./memcyber_ctl.sh [provier_name] init` コマンドを実施することでworkspace のシンボリックリンクの参照先が入れ替わり、接続先のブロックチェーンの設定を切り替えることができます。

