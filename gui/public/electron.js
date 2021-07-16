/*
 *    Copyright 2021, NTT Communications Corp.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

// Modules to control application life and create native browser window
const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const isDev = require("electron-is-dev");
const pty = require('node-pty');
const fs = require('fs');
const exec = require('util').promisify(require('child_process').exec);
const fixPath = require('fix-path');

let proc = null;

let keyFilePath = '';

const nodePtyConfig = {
  cols: 1500,
  rows: 1500,
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
    process.env.METEMCTL_KEYFILE_PASSWORD = null;
  });

  // and load the index.html of the app.
  mainWindow.loadURL(
    isDev
      ? "http://localhost:3000/login"
      : `file://${path.join(__dirname, "../build/index.html")}`
  );

  fixPath();

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




ipcMain.on('logout', async (event, arg) => {
  execLogout();
  event.returnValue = "logout";
});

ipcMain.on('login', async (event, arg) => {
  process.env.METEMCTL_KEYFILE_PASSWORD = arg;
  proc = getProc(["account", "show",]);
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
    })
  });
  await onEnd(proc);
  event.reply('login', 'success');
});

ipcMain.on('seeker', async (event, arg) => {
  proc = getProc(["seeker", "status",]);
  outputStr = "";
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(proc);
  outputs = outputStr.split(" ").filter(val => val !== '');

  let status = true;
  if (outputs[0] === 'not') {
    status = false;
  }
  event.reply('send-seekerstatus', status);
});

ipcMain.on('challange-start', async (event, arg) => {
  const challangeProc = getProc(["ix", "use", arg]);
  outputStr = "";
  let returnVal = {
    id: arg,
    name: '',
    jsonName: '',
  };

  makeData = () => {
    let outputs = outputStr.split(" ").filter(val => val !== '');

    //get name
    outputs.splice(0, outputs.indexOf('title:') + 1);
    outputs[0] = outputs[0].slice(1);  // remove "
    for (const element of outputs) {
      if (element.indexOf('".Saved') > -1) {
        returnVal.name += element.slice(0, -7);
        break;
      }
      returnVal.name += element;
    }

    //get jsonName
    returnVal.jsonName = outputs[outputs.length - 1].slice(outputs[outputs.length - 1].lastIndexOf('/') + 1).slice(0, -1);
  }

  challangeProc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
      if (val === '(type CTRL-C to quit monitoring)') {
        challangeProc.kill();
        makeData();
        event.reply('success-challange-result', returnVal);
      }
      outputStr += val;
    })
  });

  event.reply('success-challange-start', "success");
});


ipcMain.on('account', async (event, arg) => {
  let returnVal = {
    summary: {},
    contract: {},
    catalog: {},
    tokens: []
  };

  proc = getProc(["account", "show"]);

  let outputStr = "";
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(proc);
  let outputs = outputStr.split(" ").filter(val => val !== '');

  returnVal.summary.eoa_address = outputs[outputs.indexOf('Address:') + 1];
  returnVal.summary.eth_balance = `${outputs[outputs.indexOf('Balance:') + 1]} Wei`;
  outputs.splice(0, outputs.indexOf('address>') + 1);
  while (outputs.length > 0) {
    let token = {
      id: '',
      quantity: '',
      addr: ''
    };

    token.id = outputs[0].slice(0, -1);
    token.quantity = outputs[1].slice(0, -1);
    token.addr = outputs[2];

    outputs.splice(0, 3);
    returnVal.tokens.push(token);
  }

  proc = getProc(["config", "show"]);

  outputStr = "";
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(proc);
  outputs = outputStr.split(" ").filter(val => val !== '');

  returnVal.contract.catalog_address_actives = outputs[outputs.indexOf('Support/metemcyber/workspace[catalog]actives') + 2].substring(0, 42);
  returnVal.contract.catalog_address_reserves = outputs[outputs.indexOf('Support/metemcyber/workspace[catalog]actives') + 4].substring(0, 42);

  let brokerIndex = 0;
  for (let i = 0; i < outputs.length; i++) {
    if (outputs[i].indexOf('[broker]address') > -1) {
      brokerIndex = i;
      break;
    }
  }

  returnVal.contract.broker_address = outputs[brokerIndex + 2].substring(0, 42);
  returnVal.contract.operator_address = outputs[brokerIndex + 4].substring(0, 42);

  event.reply('send-accountinfo', returnVal);
});

ipcMain.on('token', async (event, arg) => {
  let returnVal = {
    item: [],
  };

  let item = {
    id: '',
    name: '',
    addr: '',
    uuid: '',
    price: '',
    left: '',
    quantity: ''
  };

  proc = getProc(["ix", "search", ' ']);

  let outputStr = "";
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(proc);

  let outputs = outputStr.split(" ").filter(val => val !== '');
  outputs.splice(0, 20);

  while (outputs.length > 0) {
    item.id = outputs[0].slice(0, -1);
    item.name = outputs.slice(1, outputs.indexOf('├')).join(" ");

    outputs.splice(0, outputs.indexOf('├') + 1);

    item.uuid = outputs[2];
    item.addr = outputs[6];
    item.price = outputs[9];
    item.left = outputs[12];
    if (outputs[15] === '(you') {
      item.quantity = outputs[17].slice(0, -1);
      outputs.splice(0, outputs.indexOf('left') + 4);
    } else {
      outputs.splice(0, outputs.indexOf('left') + 1);
    }
    returnVal.item.push(item);
    item = {
      id: '',
      name: '',
      addr: '',
      uuid: '',
      price: '',
      left: '',
      quantity: ''
    };
  }

  event.reply('send-tokenlist', returnVal);
});

ipcMain.on('buy', async (event, arg) => {

  proc = getProc(["ix", "buy", arg]);
  await onEnd(proc);
  event.reply('success-buy', "success");
});

ipcMain.on('challange', async (event, arg) => {
  let returnVal = {
    item: [],
  };

  let item = {
    id: '',
    name: '',
    addr: '',
    status: '',
  };

  proc = getProc(["ix", "show"]);

  let outputStr = "";
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(proc);

  let outputs = outputStr.split(" ").filter(val => val !== '');

  while (outputs.length > 0) {
    item.id = outputs[0].slice(0, -1);
    item.name = outputs.slice(1, outputs.indexOf('├')).join(" ");

    outputs.splice(0, outputs.indexOf('├') + 1);

    item.addr = outputs[1];
    item.status = outputs[4];

    returnVal.item.push(item);
    item = {
      id: '',
      name: '',
      addr: '',
      status: '',
    };
    outputs.splice(0, 5);
  }

  event.reply('send-challangeList', returnVal);
});

ipcMain.on('cancel', async (event, arg) => {

  proc = getProc(["ix", "cancel", arg]);
  await onEnd(proc);
  event.reply('success-cancel', "success");
});

ipcMain.on('get-key', async (event, arg) => {
  // get key path
  const keyProc = getProc(["config", "show"]);

  let outputStr = "";
  keyProc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(keyProc);
  let outputs = outputStr.split(" ").filter(val => val !== '');

  //search text 'keyfile'
  for (let i = 0; i < outputs.length; i++) {
    if (outputs[i].indexOf('keyfile') > -1) {
      outputs.splice(0, i + 2);
      break;
    }
  }
  for (let i = 0; i < outputs.indexOf('='); i++) {
    keyFilePath += `${outputs[i]}\\ `;
  }
  keyFilePath = keyFilePath.slice(0, -11);
  event.returnValue = keyFilePath.slice(keyFilePath.lastIndexOf('/') + 1);
});

ipcMain.on('exec-init', async (event, arg) => {
  event.reply('send-log', "__dirname");
  event.reply('send-log', __dirname);
  event.reply('finish-init');
});

ipcMain.on('get-image-dir', async (event, arg) => {
  event.returnValue = isDev ? './' : `file://${path.join(__dirname, "../build/")}`;
});

ipcMain.on('set-key', async (event, arg) => {
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

ipcMain.on('open-download-dir', async (event, arg) => {
  const downloadProc = getProc(["config", "show"]);

  let outputStr = "";
  downloadProc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(downloadProc);
  let outputs = outputStr.split(" ").filter(val => val !== '');

  //search text '[seeker]downloaded_cti_path'
  for (let i = 0; i < outputs.length; i++) {
    if (outputs[i].indexOf('[seeker]downloaded_cti_path') > -1) {
      outputs.splice(0, i + 2);
      break;
    }
  }
  let downloadDir = '';
  for (let i = 0; i < outputs.indexOf('='); i++) {
    downloadDir += `${outputs[i]}\\ `;
  }
  downloadDir = downloadDir.slice(0, -16);
  exec(`open ${downloadDir}`);
  event.returnValue = "success";
});


function execLogout() {
  // Making
};

function getProc(commands) {
  console.log(commands)
  return pty.spawn('metemctl', commands, nodePtyConfig);
};

function onEnd(proc) {
  return new Promise((resolve) => {
    proc.on('end', () => {
      proc.kill();
      resolve();
    });
  })
}
