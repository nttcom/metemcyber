// Modules to control application life and create native browser window
const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const isDev = require("electron-is-dev");
const pty = require('node-pty');
const ngrok = require('ngrok');
const fs = require('fs');

let proc = null;
let addr = "";

let menu = 0;
let ptyStatus = '';

let challangeStatus = {
  url: '',
  token: '',
  title: '',
  addr: ''
};
let successGetChallange = false;

const keyFilePath = isDev ? "../keyfile" : path.join(__dirname, '../../../metemcyber_contents/keyfile');
const ctlPath = isDev ? path.join(__dirname, '../../metemcyber_ctl.sh') : path.join(__dirname, '../../../metemcyber_contents/metemcyber_ctl.sh');
const workDir = isDev ? '../' : path.join(__dirname, '../../../metemcyber_contents/')

const nodePtyConfig = {
  cols: 1500,
  rows: 1500,
  cwd: workDir
};

async function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1600,
    height: 1200,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  })

  mainWindow.on('close', function () { //   <---- Catch close event
    console.log("close");
    execLogout();
  });

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

let outputText = "";
let endText = "";
async function getOutput(input, endStr, replaces = []) {
  ptyStatus = 'getOutput'
  endText = endStr;
  await new Promise((resolve) => {
    const intervalId = setInterval(() => {
      if (ptyStatus === 'finishOutput') {
        resolve();
      }
    }, 100);
    proc.write(input + "\n");
  });
  ptyStatus = 'waitChallange';
  let returnVal = outputText;
  outputText = "";
  endText = "";

  replaces.map((val) => {
    returnVal = returnVal.replace(val[0], val[1]);
  })
  returnVal = returnVal.split(" ").filter(val => val !== '')
  console.log(returnVal);
  return returnVal;
}

ipcMain.on('select-logout', async (event, arg) => {
  execLogout();
  event.returnValue = "logout";
});

ipcMain.on('login', async (event, arg) => {
  // Get keyfile name.
  const keyfileName = fs.readdirSync(keyFilePath);
  ptyStatus = 'login';
  // Create the browser window.
  proc = pty.spawn('bash', [
    ctlPath,
    "-",
    "client",
    `-f  keyfile/${keyfileName[0]}`,
    `-w  ${addr}`
  ],
    nodePtyConfig
  );

  proc.on('data', (data) => {
    switch (ptyStatus) {
      case 'login':
        data.split("\r\n").map((val) => {
          event.reply('send-log', val);
          console.log(val)
          switch (val) {
            case 'Enter password for keyfile:':
              proc.write(arg + "\n");
              break;
            case 'コマンドを入力してください':
              event.reply('login', 'success');
              break;
            default:
              break;
          }
        })
        break;
      case 'getOutput':
        data.split("\r\n").map((val) => {
          if (!setChallangeStatus(val)) {
            switch (val) {
              case endText:
                ptyStatus = 'finishOutput'
                break;
              default:
                outputText += val;
                break;
            }
          }
        })
        break;
      case 'waitChallange':
        callbackChallange(data);
        break;
      default:
        console.log("default")
        break;
    }
  });


});

ipcMain.on('get-key', async (event, arg) => {
  fs.readdir(keyFilePath, (err, files) => {
    if (err) {
      console.error(err);
    };

    if (files.length === 0) {
      event.returnValue = "Key file does not exist";
    }
    event.returnValue = files[0];
  });
});

ipcMain.on('exec-init', async (event, arg) => {
  const exec = require('util').promisify(require('child_process').exec);

  const dockerPath = fs.readFileSync(isDev ? "./docker-path" : path.join(__dirname, '../../../docker-path'), 'utf8').toString().split('¥n');
  process.env.PATH = `${dockerPath}:${process.env.PATH}`;

  event.reply('send-log', "__dirname");
  event.reply('send-log', __dirname);

  const echoRes = await exec('echo $PATH');
  event.reply('send-log', "echo result");
  event.reply('send-log', echoRes.stdout);

  const whichRes = await exec('which docker');
  event.reply('send-log', "which result");
  event.reply('send-log', whichRes.stdout);

  addr = await ngrok.connect(isDev ? 51004 : { addr: 51004, binPath: path => path.replace('app.asar', 'app.asar.unpacked') });
  event.reply('send-log', "ngrok");
  // Create the browser window.
  proc = pty.spawn('bash', [
    ctlPath,
    "pricom",
    "init",
  ],
    nodePtyConfig
  );

  await new Promise((resolve) => {
    proc.on('data', function (data) {
      data.split("\r\n").map((val) => {
        event.reply('send-log', val);
        console.log(val);
        switch (val) {
          case 'Password:':
            event.reply('get-password');
            break;
          case 'connection ok.':
            resolve();
            break;
          default:
            break;
        }
      })
    });
  });
  event.reply('finish-init');
});

ipcMain.on('set-password', async (event, arg) => {
  proc.write(arg + "\n");
});

ipcMain.on('get-imagedir', async (event, arg) => {
  event.returnValue = isDev ? './' : `file://${path.join(__dirname, "../build/")}`;
});

ipcMain.on('set-key', async (event, arg) => {
  console.log(arg);
  const fileNames = fs.readdirSync(keyFilePath);
  event.reply('send-log', fileNames);
  for (let file in fileNames) {
    fs.unlinkSync(path.join(keyFilePath, fileNames[file]));
  }
  event.reply('send-log', path.join(__dirname, `../../../metemcyber_contents/keyfile/${arg.name}`));
  try {
    fs.copyFileSync(arg.path, isDev ? `../keyfile/${arg.name}` : path.join(__dirname, `../../../metemcyber_contents/keyfile/${arg.name}`));
  } catch (e) {
    event.reply('send-log', e)
  }
  event.returnValue = "success";
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

function execLogout() {
  ptyStatus = 'logout';
  if (menu !== 0) {
    proc.write('b' + "\n");
  }
  proc.write('0' + "\n");
  proc.kill();
};
