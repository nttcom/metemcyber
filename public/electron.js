// Modules to control application life and create native browser window
const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const isDev = require("electron-is-dev");
const pty = require('node-pty');
const ngrok = require('ngrok');
const fs = require('fs');

let proc = [];
let addr = "";

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
      ? "http://localhost:3000"
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
  const returnVal = [];
  proc.on('data', function (data) {
    data.split("\r\n").map((val) => {
      console.log(val)
      switch (val) {
        case 'コマンドを入力してください':
          event.returnValue = returnVal;
          break;
        default:
          returnVal.push(val);
          break;
      }
    })
  });
  proc.write(arg + "\n");
});

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

  proc.on('data', function (data) {
    data.split("\r\n").map((val) => {
      console.log(val)
      switch (val) {
        case 'Enter password for keyfile:':
          proc.write(arg + "\n");
          break;
        case 'コマンドを入力してください':
          console.log("IN menu")
          event.reply('login', 'success');
          //proc.write('1' + "\n");
          // return        
          break;
        default:
          break;
      }
    })
  });

});
