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


// 同期メッセージの受信と返信
ipcMain.on('synchronous-message', (event, arg) => {
  console.log('node.js console arg:' + arg)
  //proc.write(arg + "\n");
  // return
  event.returnValue = 'success'

});

ipcMain.on('select-menu', async (event, arg) => {
  console.log('arg:' + arg)
  const output = await getOutput(arg, 'コマンドを入力してください');

  let returnVal = {
    summary: {},
    contract: {},
    catalog: {},
    token: {}
  };
  output.map((val) => {
    if (val.indexOf("EOAアドレス") !== -1) {
      returnVal.summary.eoa_address = val.split(" ").slice(-1)[0];
    } else if (val.indexOf("所持ETH") !== -1) {
      returnVal.summary.eth_balance = val.split(" ").slice(-2)[0];
    } else if (val.indexOf("カタログアドレス") !== -1) {
      returnVal.contract.catalog_address = val.split(" ").slice(-1)[0];
    } else if (val.indexOf("ブローカーアドレス") !== -1) {
      returnVal.contract.broker_address = val.split(" ").slice(-1)[0];
    } else if (val.indexOf("オペレータアドレス") !== -1) {
      returnVal.contract.operator_address = val.split(" ").slice(-1)[0];
    } else if (val.indexOf("所持ユニークCTIトークン数") !== -1) {
      returnVal.catalog.number_of_unique_token = val.split(" ").slice(-1)[0];
    } else if (val.indexOf("CTIトークン発行回数") !== -1) {
      returnVal.catalog.number_of_token_issue = val.split(" ").slice(-1)[0];
    }
  })
  event.returnValue = returnVal;
});

async function getOutput(input, endStr) {
  const returnVal = [];
  await new Promise((resolve) => {
    proc.on('data', function (data) {
      data.split("\r\n").map((val) => {
        switch (val) {
          case endStr:
            resolve();
            break;
          default:
            returnVal.push(val);
            break;
        }
      })
    });
    proc.write(input + "\n");
  })
  return returnVal;
}

ipcMain.on('select-logout', async (event, arg) => {
  proc.write('0' + "\n");
  event.returnValue = "logout";
});

ipcMain.on('login', async (event, arg) => {
  const keyfileDir = './keyfile';
  let keyfileName = '';
  // Get keyfile name.
  fs.readdir(keyfileDir, (err, files) => {
    if (err) throw err;
    keyfileName = files[0];
  });

  addr = await ngrok.connect(51004);
  console.log(addr);

  // Create the browser window.
  proc = pty.spawn('bash', [
    `metemcyber_ctl.sh`,
    "-",
    "client",
    `-f  ${keyfileDir}/${keyfileName}`,
    `-w  ${addr}`
  ],
    {
      cols: 80,
      rows: 30,
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
            console.log("IN menu")
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
