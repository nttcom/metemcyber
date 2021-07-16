## 実行環境
OS:Ubuntu 18.04
node.js:14.15.5
npm:6.14.11

## npm startによるGUI実行方法

### パッケージのインストール

以下コマンドをmetemcyber/guiディレクトリ内で実行
```
npm install
```

### 鍵ファイルの配置

metemcyberディレクトリ直下に'keyfile'ディレクトリを作成後、'keyfile'ディレクトリ内に鍵ファイルを配置

### GUIの起動

以下コマンドをmetemcyber/guiディレクトリ内で実行
```
npm start
```

エラーが発生する場合以下を実行後、再度GUIを起動してみてください
```
npx electron-rebuild
```

## Metemcyber.appを使用したGUI実行方法（macOSのみ）

### 鍵ファイルの配置

Metemcyber.app内のContents/metemcyber_contentsディレクトリ直下に'keyfile'ディレクトリを作成後、'keyfile'ディレクトリ内に鍵ファイルを配置

### Metemcyber.app内のMetemcyber実行環境を初期化

以下コマンドをMetemcyber.app内のContents/metemcyber_contentsディレクトリ内で実行
```
./metemcyber_ctl.sh pricom init
```

### Metemcyber.appの拡張属性を削除

Web経由でMetemcyber.appをダウンロードした場合、起動ディレクトリが異なってしまう為、以下コマンドをmetemcyber/guiディレクトリ内で実行
```
xattr -d com.apple.quarantine Metemcyber.app
```
