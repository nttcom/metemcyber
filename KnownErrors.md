# 既知のエラーと対処方法



### クライアントを起動できない

```
$ ./metemcyber_ctl.sh pricom client -f ~/.ethereum/keystore/UTC--my-keyfile
initializing ./workspace/docker.env.
docker: Error response from daemon: network metemcyber-pricom not found.
```

初期構築が未実施です。`metemcyber_ctl.sh pricom init` を実行してください。

---

```
 => ERROR [internal] load metadata for docker.io/library/ubuntu:20.04
------
 > [internal] load metadata for docker.io/library/ubuntu:20.04:
------
failed to solve with frontend dockerfile.v0: .....
```

データの自動取得が行われないケースがあるようです。
`docker pull docker.io/library/ubuntu:20.04` を実行してから再実行してください。

---

```
$ ./metemcyber_ctl.sh pricom client alice
not yet initialized
```

alice, bob, carol のアカウントはテストプロバイダ環境（ganache や besu）でのみ使用可能です。pricom では使用できません。

---

```
$ ./metemcyber_ctl.sh pricom client -f ~/.ethereum/keystore/UTC--my-keyfile
Enter password for keyfile:
ERROR: MAC mismatch
cannot decode keyfile: UTC--my-keyfile
```

キーファイルに対するパスワード違いで発生します。
正しいパスワードを入力してください。

---

### クライアント操作でエラーが発生する

```
requests.exceptions.HTTPError: 400 Client Error: Bad Request for url: https://rpc.metemcyber.ntt.com/
```

Ether を消費する操作を行った場合であれば、保有 Ether が不足している可能性があります。保有 Ether 量を確認し、必要であれば補充してください。誤ったアカウントでログインしている可能性も考えられます。

クライアントプログラム起動直後に発生する場合、workspace.pricom/config.ini が破損している可能性があります。最新の config.ini を取得・配置してください。

### チャレンジに失敗する

```
チャレンジトークンが返還されました: 0x2188775902595a880c4C2FC682602D1f71c18209
メッセージが添付されています: cannot sendback result via webhook: <urlopen error [Errno -2] Name or service not known>
（あるいは）
メッセージが添付されています: cannot sendback result via webhook: <urlopen error [Errno 99] Cannot assign requested address>
（など）
```

あなたが実行しているクライアントプログラムに対する、トークン提供者の solver プログラムからの webhook 接続が失敗しています。前者（Name or service not known）は URL の名前解決に失敗した場合、後者（Cannot assign requested address）は名前解決できたが接続拒否された場合に発生します。timeout など、他のエラーメッセージの場合もあります。

metemcyber のマニュアルをご参照のうえ、必要であれば ngrok のセットアップなどを実施してください。また、クライアントプログラム実行時のオプション指定間違いなどにご注意ください。

なお、ネットワーク接続障害は metemcyber とは無関係に発生している可能性も考えられます。metemcyber とは別のプログラム（例えばWebブラウザ）などで接続性を確認し、問題がある場合は当該ネットワークの管理者にご確認ください。

* 補足

  名前解決の失敗は、クライアントプログラム実行時の -w オプションの付け忘れで発生しやすいです。その他のエラーは firewall によるアクセス制限などが考えられます。dockerの問題（コンテナ-ホスト間通信）に起因するケースもあるようです。

---

```
チャレンジトークンが返還されました: 0x2188775902595a880c4C2FC682602D1f71c18209
メッセージが添付されています: Challenge failed by solver side error
```

トークン出品者の solver プログラムで生じた不具合により、チャレンジが失敗しています。（現在の実装仕様では、購入者側ではチャレンジを再実行する以外に行えることはありません）

* トークン出品者（solver プログラム稼働者）側へのヒント

  ストレージサービスへのアップロードに失敗している可能性が考えられます。API キーが正しく、また失効していないことを確認してください。

---

```
-------------------- 
チャレンジの処理を開始しました
-------------------- 
と表示された後、いつまで経っても完了しない（成否が表示されない）
```

まず、メニューの「[12]タスク（チャレンジ）のキャンセル」を実行してください。ここで「選択できるアイテムがありません」と表示される場合、既にタスクは受理されており処理中です。そのままお待ちください。

実行したタスクがリストに表示される場合、当該タスクは未受理状態です。当該トークンの出品者が solver プログラムを稼働させていないか、不具合が生じている可能性があります。seeker プログラム（クライアントプログラム）を停止したいような場合、タスクをキャンセルして後に再実行することもできます。キャンセルするとチャレンジトークンは返還されます。

---
```
--------------------
チャレンジに成功しました！！！
--------------------
受信 URL: https://storage.googleapis.com/metemcyber-storage-1/81f608afa......
トークン: 0x8b295504c23E9Aa5f7dA30d574B4a9e2CA06cA61
チャレンジ結果を受信しましたが、受信URLからのダウンロードに失敗しました: <urlopen error [Errno -2] Name or service not known>
手動でダウンロードしてください
```

何らかの理由により、クライアントプログラムから指定URLへのアクセスに失敗しています。プロキシサーバが介在するようなネットワーク環境で発生しがちです。
表示されているURLから、Webブラウザなどを使用して手動でダウンロードしてください。
なお、提示されているダウンロードURLは一定時間で失効する場合がありますので、ご留意ください。

* 補足

  metemcyber.settings に `HTTP_PROXY`, `HTTPS_PROXY` の環境変数を設定することで解決する可能性があります。


