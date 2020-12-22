MISPのセットアップ
==================

| Metemcyberは、`MISP <https://www.misp-project.org/>`_ というオープンソースの脅威情報共有プラットフォームを用いてCTIの共有を実現します。 
| MISPは、脅威インテリジェンスを蓄積・共有・関連づけを行うオープンソースソフトウェアです。
| 組織はMISPを活用することで、脅威インテリジェンスを効率的に蓄積・共有し、脅威インテリジェンスを活用したセキュリティオペレーションを実施することができます。
| MISPの詳細を知りたい場合は、`MISP公式サイトの解説 <https://www.misp-project.org/features.html>`_ 、もしくは公式サイトのトレーニング資料や講演資料などを参考にしてください。

    * `MISP公式サイト <https://www.circl.lu/services/misp-training-materials/>`_
    * `Githubのtrainingレポジトリ <https://github.com/MISP/misp-training>`_

| このページでは、MISPの概要、インストール方法、イベントの作成方法について紹介いたします。

MISPのインストール
------------------

| MISPのインストール方法は、`MISP公式ページ <https://www.misp-project.org/download/>`_ に記載されています。
| インストール方法は、いくつかの選択肢があります。

公式のインストールガイドを使う場合
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
| サーバ上に直接MISPをインストールする場合は、MISP公式が提供する `MISP Install Documentation <https://misp.github.io/MISP/>`_ に従います。
| 例として、Ubuntu 18.04の場合は以下のコマンドでインストール可能です。

    .. code-block:: bash

        # インストールスクリプトのダウンロード
        wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
        # インストールスクリプトの実行
        bash /tmp/INSTALL.sh

dockerを使う方法
~~~~~~~~~~~~~~~~
| MISPのdockerイメージはいくつか公式サイトで紹介されていますが、現在は `docker-misp <https://github.com/MISP/docker-misp>`_ を利用するのがよいと思われます。

