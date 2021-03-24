// Modules to control application life and create native browser window
const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const isDev = require("electron-is-dev");
const pty = require('node-pty');
const ngrok = require('ngrok');
const fs = require('fs');

let proc = [];
let addr = "";

let menu = 0;

let challangeStatus = {
  url: '',
  token: '',
  title: '',
  addr: ''
};
let successGetChallange = false;

async function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1600,
    height: 1200,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  })

  // and load the index.html of the app.
  mainWindow.loadURL(
    isDev
      ? "http://localhost:3000/login"
      : `file://${path.join(__dirname, "../build/index.html")}`
  );

  // Open the DevTools.
  mainWindow.webContents.openDevTools()
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.whenReady().then(() => {
  createWindow()

  app.on('activate', function () {
    // On macOS it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit()
})

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and require them here.

ipcMain.on('select-menu', async (event, arg) => {
  console.log('arg:' + arg)
  let returnVal = {};
  if (menu !== 0) {
    await getOutput("b", 'コマンドを入力してください');
  }

  let output = [];
  switch (arg) {
    case '1':
      output = await getOutput(arg, 'コマンドを入力してください', [[/--------------------/g, " "], [/■/g, ""], [/ID:/g, " ID:"]]);
      returnVal = extractOutput1(output);
      menu = 0;
      break;
    case '10':
      output = await getOutput(arg, '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/left/g, "left "], [/^.* solver/, ""]]);
      returnVal = extractOutputToken(output);
      menu = 10;
      break;
    case '11':
      output = await getOutput(arg, '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/left/g, "left "], [/^.* solver/, ""]]);
      returnVal = extractOutputToken(output);
      menu = 11;
      break;
    case '12':
      output = await getOutput(arg, '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/\[ \]インデックスを入力して選択する/g, " [ ]インデックスを入力して選択する"]]);
      if (output[0].indexOf('検索中') === -1) {
        output.shift();
      } else {
        output.splice(0, 3);
      }
      returnVal = extractOutput12(output);
      menu = 12;
      break;
    default:
      break;
  }

  event.returnValue = returnVal;
});

ipcMain.on('select-10', async (event, arg) => {
  console.log('arg:' + arg)
  let returnVal = {};
  let output = [];

  if (arg[0] === 's') {
    proc.write('s' + "\n");
    output = await getOutput(arg[1], '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/left/g, "left "], [/^.* solver/, ""]]);
  } else if (arg[0] === 'a') {
    output = await getOutput('a', '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/left/g, "left "], [/^.* solver/, ""]]);
  } else {
    proc.write(arg[0] + "\n");
    output = await getOutput('1', '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/left/g, "left "], [/^.* solver/, ""]]);
  }
  returnVal = extractOutputToken(output);

  event.returnValue = returnVal;
});

ipcMain.on('select-11', async (event, arg) => {
  console.log('arg:' + arg)
  let returnVal = {};
  let output = [];

  if (arg[0] === 's') {
    proc.write('s' + "\n");
    output = await getOutput(arg[1], '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/left/g, "left "], [/^.* solver/, ""]]);
    returnVal = extractOutputToken(output);
  } else if (arg[0] === 'a') {
    output = await getOutput('a', '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/left/g, "left "], [/^.* solver/, ""]]);
    returnVal = extractOutputToken(output);
  } else {
    await getOutput(arg[0], '[0]:終了');
    output = await getOutput('11', '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/left/g, "left "], [/^.* solver/, ""]]);
    returnVal = extractOutputToken(output);
    menu = 11;
  }

  event.returnValue = returnVal;
});

ipcMain.on('select-12', async (event, arg) => {
  console.log('arg:' + arg)
  let returnVal = {};
  let output = [];

  if (arg[0] === 's') {
    proc.write('s' + "\n");
    output = await getOutput(arg[1], '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/\[ \]インデックスを入力して選択する/g, " [ ]インデックスを入力して選択する"]]);
    if (arg[1] === '') {
      output.shift();
    } else {
      output.splice(0, output.indexOf(')') + 1);
    }
    returnVal = extractOutput12(output);
  } else if (arg[0] === 'a') {
    output = await getOutput(arg, '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/\[ \]インデックスを入力して選択する/g, " [ ]インデックスを入力して選択する"]]);
    output.shift();
    returnVal = extractOutput12(output);
  } else {
    await getOutput(arg[0], '[0]:終了');
    output = await getOutput('12', '[s]アイテムを検索する', [[/├/g, " "], [/└/g, " "], [/\[ \]インデックスを入力して選択する/g, " [ ]インデックスを入力して選択する"]]);
    if (output[0].indexOf('検索中') === -1) {
      output.shift();
    } else {
      output.splice(0, 3);
    }
    returnVal = extractOutput12(output);
    menu = 12;
  }

  event.returnValue = returnVal;
});

ipcMain.on('get-challange', async (event) => {
  console.log('get challange...')
  if (successGetChallange) {
    event.reply('set-challange', challangeStatus);
    successGetChallange = false;
    challangeStatus = {
      url: '',
      token: '',
      title: '',
      dataDir: '',
      challangeToken: ''
    };
  }
});


function extractOutput1(output) {
  let returnVal = {
    summary: {},
    contract: {},
    catalog: {},
    tokens: []
  };

  returnVal.summary.eoa_address = output[output.indexOf('EOAアドレス:') + 1];
  returnVal.summary.eth_balance = `${output[output.indexOf('所持ETH:') + 1]} Wei`;
  returnVal.contract.catalog_address = output[output.indexOf('カタログアドレス:') + 1];
  returnVal.contract.broker_address = output[output.indexOf('ブローカーアドレス:') + 1];
  returnVal.contract.operator_address = output[output.indexOf('オペレータアドレス:') + 1];
  returnVal.catalog.number_of_unique_token = output[output.indexOf('所持ユニークCTIトークン数:') + 1];
  returnVal.catalog.number_of_token_issue = output[output.indexOf('CTIトークン発行回数:') + 1];

  let tokens = output.slice(output.indexOf('CTIトークン') + 1, -1);
  while (tokens.length > 1) {
    let token = {
      id: '',
      quantity: '',
      addr: ''
    };

    token.id = tokens[0].slice(tokens[0].indexOf(':') + 1);
    token.quantity = tokens[1].slice(tokens[1].indexOf(':') + 1);
    token.addr = tokens[3];

    tokens.splice(0, 4);
    returnVal.tokens.push(token);
    token = {
      id: '',
      quantity: '',
      addr: ''
    };
  }

  console.log(returnVal);
  return returnVal;
}

function extractOutput12(output) {
  let returnVal = {
    item: [],
  };

  let item = {
    id: '',
    name: '',
    addr: '',
    state: ''
  };

  if (output.length === 0) {
    return returnVal;
  }

  while (output[0].indexOf(':') !== -1) {

    //値チェック
    if (output.indexOf('Addr') === -1 && output.indexOf('State:') === -1) {
      break;
    }
    item.id = output[0].slice(0, -1);
    item.name = output.slice(1, output.indexOf('Addr')).join(" ");

    output.splice(0, output.indexOf('Addr'));

    output.slice(output.indexOf('Addr') + 2, output.indexOf('State:')).map((val) => {
      console.log(val);
      item.addr += val;
    })

    item.state = output[output.indexOf('State:') + 1];

    output.splice(0, 5);
    returnVal.item.push(item);
    item = {
      id: '',
      name: '',
      addr: '',
      state: ''
    };
  }

  console.log(returnVal);
  return returnVal;
}

function extractOutputToken(output) {
  let returnVal = {
    item: [],
  };

  let item = {
    id: '',
    name: '',
    addr: '',
    uuid: '',
    price: '',
    left: ''
  };

  while (output[0].indexOf(':') !== -1) {

    //値チェック
    if (output.indexOf('Addr') === -1 && output.indexOf('UUID') === -1) {
      break;
    }
    item.id = output[0].slice(0, -1);
    item.name = output.slice(1, output.indexOf('Addr')).join(" ");

    output.splice(0, output.indexOf('Addr'));

    output.slice(output.indexOf('Addr') + 2, output.indexOf('UUID')).map((val) => {
      console.log(val);
      item.addr += val;
    })

    output.slice(output.indexOf('UUID') + 2, output.indexOf('Price:')).map((val) => {
      item.uuid += val;
    })

    item.price = output[output.indexOf('Price:') + 1];
    item.left = output[output.indexOf('tokens') - 1];

    output.splice(0, output.indexOf('left') + 1);
    returnVal.item.push(item);
    item = {
      id: '',
      name: '',
      addr: '',
      uuid: '',
      price: '',
      left: ''
    };
  }

  console.log(returnVal);
  return returnVal;
}

async function getOutput(input, endStr, replaces = []) {
  let returnVal = "";
  await new Promise((resolve) => {
    proc.on('data', function (data) {
      data.split("\r\n").map((val) => {
        if (!setChallangeStatus(val)) {
          switch (val) {
            case endStr:
              resolve();
              break;
            default:
              returnVal += val;
              break;
          }
        }
      })
    });
    proc.write(input + "\n");
  })
  proc.on('data', (data) => { callbackChallange(data) });
  console.log(returnVal);
  replaces.map((val) => {
    returnVal = returnVal.replace(val[0], val[1]);
  })
  returnVal = returnVal.split(" ").filter(val => val !== '')
  console.log(returnVal);
  return returnVal;
}

ipcMain.on('select-logout', async (event, arg) => {
  proc.on('data', () => { });
  if (menu !== 0) {
    proc.write('b' + "\n");
  }
  proc.write('0' + "\n");
  event.returnValue = "logout";
});

ipcMain.on('login', async (event, arg) => {
  let keyfileName = '';
  // Get keyfile name.
  fs.readdir(isDev ? "../keyfile" : path.join(__dirname, '../keyfile'), (err, files) => {
    if (err) throw err;
    keyfileName = files[0];
  });

  addr = await ngrok.connect(isDev ? 51004 : { addr: 51004, binPath: path => path.replace('app.asar', 'app.asar.unpacked') });

  // Create the browser window.
  proc = pty.spawn('bash', [
    '../metemcyber_ctl.sh',
    "-",
    "client",
    `-f  keyfile/${keyfileName}`,
    `-w  ${addr}`
  ],
    {
      cols: 1500,
      rows: 1500,
      cwd: isDev ? "./" : '../',
      env: process.env
    }
  );

  await new Promise((resolve) => {
    proc.on('data', function (data) {
      data.split("\r\n").map((val) => {
        console.log(val)
        switch (val) {
          case 'Enter password for keyfile:':
            proc.write(arg + "\n");
            break;
          case 'コマンドを入力してください':
            resolve();
            break;
          default:
            break;
        }
      })
    });

  })
  event.reply('login', 'success');
});

function callbackChallange(data) {
  data.split("\r\n").map((val) => {
    setChallangeStatus(val);
  });
};

function setChallangeStatus(val) {
  let status = false;
  if (val.indexOf('受信 URL: ') === 0) {
    challangeStatus.url = val.slice(8);
    status = true;
  } else if (val.indexOf('トークン: ') === 0) {
    challangeStatus.token = val.slice(6);
    status = true;
  } else if (val.indexOf('取得データタイトル: ') === 0) {
    challangeStatus.title = val.slice(11);
    status = true;
  } else if (val.indexOf('取得データを保存しました: ') === 0) {
    challangeStatus.dataDir = val.slice(14);
    status = true;
  } else if (val.indexOf('チャレンジトークンが返還されました: ') === 0) {
    challangeStatus.challangeToken = val.slice(19);
    status = true;
    successGetChallange = true;
  }
  return status;
}
