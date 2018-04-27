# custom-request-handler
This extension is customized for "Rule Actoins" in "Session Handling Rules".

## Features
* Automaticaly overwrites JSON and Headers with handled request from macro function.
* You can configure a simple list of string that are used as payloads.(This is similar to "Intruder".)

# Installation
Jython 2.7+ is required for this extension to work to set it up in Burp's Extender Options before adding the extension. 

# User guide - How to use?
### Standard settings.
1. Click "Project options" > "Sessions" > "Session Handling Rules" > "add".
2. Setting macros.
3. Select "After running the macro. invoke a Burp extension handler".
4. Select "custom request handler" from dropdown menu.
5. Click "OK".

### Automaticaly overwrite parameters
1. Right-click in a tab with http/https response and click "Send to CRH".
2. Select target type(JSON/Header) in "Extract target strings".
3. Enter name of the target to overwrite.
4. Click "Add".
5. Go to "Repeater", "Intruder" etc and Click "Go".

### Payload sets
1. Select target type(JSON/Header) in "Extract target strings".
2. Enter name of the target to overwrite.
3. Click "Load" and select file of simple list.
4. Go to "Repeater", "Intruder" etc and Click "Go".


# custom-request-handler
これはSession Handling RulesのRule Actoinsを拡張したもの。

# 特徴
* マクロ機能から渡されたrequestのJSONとヘッダを自動で書き換えることができる。
* simple listからペイロードを設定できる。(Intruderのsimple listとほぼ同じ)

# ユーザーガイド
### 標準設定
1. "Project options" > "Sessions" > "Session Handling Rules" > "add" をクリックする。
2. マクロを設定する
3. "After running the macro. invoke a Burp extension handler"にチェックを入れる
4. ドロップダウンメニューから"custom request handler"を選択する
5. "OK"をクリックする

### パラメータの自動上書き
1. httpかhttpsレスポンスがあるタブ(HistoryやRepeaterなど)で右クリックして"Send to CRH"をクリックする
2. 対象のタイプ(JSON/Header)を選択する
3. 書き換える対象のパラメータ名を入力する
4. "Add"をクリックする
5. 対象のリクエストを送信する

### ペイロードの設定
1. 対象のタイプ(JSON/Header)を選択する
2. 書き換える対象のパラメータ名を入力する
3. Loadボタンをクリックして、読み込みたいファイルを選択する
4. 対象のリクエストを送信する
