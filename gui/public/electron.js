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

const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const isDev = require("electron-is-dev");
const pty = require('node-pty');
const fs = require('fs');
const exec = require('util').promisify(require('child_process').exec);
const fixPath = require('fix-path');
const electronStore = require('electron-store');
const store = new electronStore();

const nodePtyConfig = {
  cols: 1500,
  rows: 1500,
};

const failedMessage = /failed operation:/;

async function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1600,
    height: 1200,
    minHeight: 500,
    minWidth: 865,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js')
    }
  })

  mainWindow.on('close', function () { //   <---- Catch close event
    console.log("close");
    process.env.METEMCTL_KEYFILE_PASSWORD = null;
  });

  // change EDITOR in environment variable to 'vi'
  process.env.EDITOR = 'vi';
  // and load the index.html of the app.
  mainWindow.loadURL(
    isDev
      ? "http://localhost:3000/login"
      : `file://${path.join(__dirname, "../build/index.html")}`
  );

  fixPath();

  if (!store.get('TRANSACTION_API_URL', false)) {
    store.set('TRANSACTION_API_URL', '')
  }
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


ipcMain.on('logout', async (event, arg) => {
  process.env.METEMCTL_KEYFILE_PASSWORD = '';
  event.returnValue = "logout";
});

ipcMain.on('login', async (event, arg) => {
  let commandStatus = true;
  let message = '';

  process.env.METEMCTL_KEYFILE_PASSWORD = arg;
  const proc = getProc(["account", "show",]);
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      if (val.match(failedMessage)) {
        commandStatus = false;
        message = val;
      }
      event.reply('send-log', val);
    })
  });
  await onEnd(proc);
  event.reply('login', {
    'commandStatus': commandStatus,
    'message': message
  });
});

ipcMain.on('seeker', async (event, arg) => {
  let commandStatus = true;
  let message = '';

  let seekerStatus = true;

  const proc = getProc(["seeker", "status",]);
  outputStr = "";
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      if (val.match(failedMessage)) {
        commandStatus = false;
        message = val;
        seekerStatus = false;
      }
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(proc);

  if (!commandStatus) {
    event.reply('send-seekerstatus', {
      'commandStatus': commandStatus,
      'message': message
    });
    return;
  }

  outputs = outputStr.split(" ").filter(val => val !== '');

  if (outputs[0] === 'not') {
    seekerStatus = false;
  }

  event.reply('send-seekerstatus', {
    'commandStatus': commandStatus,
    'message': message,
    'data': {
      'seekerStatus': seekerStatus
    }
  });
});

ipcMain.on('challange-start', async (event, arg) => {
  const proc = getProc(["ix", "use", arg]);
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

  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
      if (val === '(type CTRL-C to quit monitoring)') {
        proc.kill();
        makeData();
        event.reply('success-challange-result', returnVal);
      }
      outputStr += val;
    })
  });

  event.reply('success-challange-start', "success");
});


ipcMain.on('account', async (event, arg) => {
  let commandStatus = true;
  let message = '';

  let returnVal = {
    summary: {},
    contract: {},
    catalog: {},
    tokens: []
  };

  let proc = getProc(["account", "show"]);

  let outputStr = "";
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      if (val.match(failedMessage)) {
        commandStatus = false;
        message = val;
      }
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(proc);

  if (!commandStatus) {
    event.reply('send-accountinfo', {
      'commandStatus': commandStatus,
      'message': message
    });
    return;
  }

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
      if (val.match(failedMessage)) {
        commandStatus = false;
        message = val;
      }
      outputStr += val;
    })
  });
  await onEnd(proc);

  if (!commandStatus) {
    event.reply('send-accountinfo', {
      'commandStatus': commandStatus,
      'message': message
    });
    return;
  }

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

  event.reply('send-accountinfo', {
    'commandStatus': commandStatus,
    'message': message,
    'data': {
      'accountInfo': returnVal
    }
  });
});

ipcMain.on('token', async (event, arg) => {
  let commandStatus = true;
  let message = '';

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

  const proc = getProc(["ix", "search", ' ']);

  let outputStr = "";
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      if (val.match(failedMessage)) {
        commandStatus = false;
        message = val;
      }
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(proc);

  if (!commandStatus) {
    event.reply('send-tokenlist', {
      'commandStatus': commandStatus,
      'message': message
    });
    return;
  }

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

  event.reply('send-tokenlist', {
    'commandStatus': commandStatus,
    'message': message,
    'data': {
      'tokenList': returnVal
    }
  });
});

ipcMain.on('buy', async (event, arg) => {

  const proc = getProc(["ix", "buy", arg]);
  await onEnd(proc);
  event.reply('success-buy', "success");
});

ipcMain.on('challange', async (event, arg) => {
  let commandStatus = true;
  let message = '';

  let returnVal = {
    item: [],
  };

  let item = {
    id: '',
    name: '',
    addr: '',
    status: '',
  };

  const proc = getProc(["ix", "show"]);

  let outputStr = "";
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      if (val.match(failedMessage)) {
        commandStatus = false;
        message = val;
      }
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(proc);

  if (!commandStatus) {
    event.reply('send-challangeList', {
      'commandStatus': commandStatus,
      'message': message
    });
    return;
  }

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

  event.reply('send-challangeList', {
    'commandStatus': commandStatus,
    'message': message,
    'data': {
      'challangeList': returnVal
    }
  });
});

ipcMain.on('cancel', async (event, arg) => {

  const proc = getProc(["ix", "cancel", arg]);
  await onEnd(proc);
  event.reply('success-cancel', "success");
});

ipcMain.on('get-key', async (event, arg) => {
  const keyFilePath = await getKeyFilePath(event);
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
  //get key file name
  const keyFilePath = await getKeyFilePath(event);

  const lastSlashIndex = keyFilePath.lastIndexOf('/') + 1;

  const keyFileName = keyFilePath.slice(lastSlashIndex);
  const keyFileDir = keyFilePath.slice(0, lastSlashIndex);

  // change key file name in config
  const proc = getProc(["config", "edit"]);
  proc.write(`:%s/${keyFileName}/${arg.name}/` + '\n');
  proc.write(':wq' + '\n');
  await onEnd(proc);

  // add key file
  try {
    fs.copyFileSync(arg.path, `${keyFileDir}${arg.name}`);
  } catch (e) {
    event.reply('send-log', e)
  }

  event.returnValue = "success";
});

ipcMain.on('open-download-dir', async (event, arg) => {
  const proc = getProc(["config", "show"]);

  let outputStr = "";
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(proc);
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

ipcMain.on('get-transaction', async (event, arg) => {
  const request = require('request');
  console.log(arg);
  request.post({
    uri: `${store.get('TRANSACTION_API_URL')}/tx_counter`,
    headers: { "Content-type": "application/json" },
    json: [{
      "class": "DailyActivity",
      "options": {
        "generic_filter": {
          "include_from": arg.address
        },
        "start": `${arg.startYear}-${arg.startMonth}-${arg.startDate}T15:00:00`,
        "end": `${arg.endYear}-${arg.endMonth}-${arg.endDate}T15:00:00`
      }
    }]
  }, (err, res, data) => {
    if (res.statusCode === 200) {
      event.reply('send-transaction', data[0]);
    } else {
      event.reply('send-transaction', false);
    }
  });
});

ipcMain.on('get-password', async (event, arg) => {
  event.returnValue = require('shell-env').sync().METEMCTL_KEYFILE_PASSWORD;
});

ipcMain.on('get-transaction-url', async (event, arg) => {
  event.returnValue = store.get('TRANSACTION_API_URL');
});

ipcMain.on('set-transaction-url', async (event, arg) => {
  store.set('TRANSACTION_API_URL', arg);
  event.returnValue = 'success';
});

async function getKeyFilePath(event) {
  // get key path
  const proc = getProc(["config", "show"]);

  let outputStr = "";
  proc.on('data', (data) => {
    data.split("\r\n").map((val) => {
      event.reply('send-log', val);
      outputStr += val;
    })
  });
  await onEnd(proc);
  let outputs = outputStr.split(" ").filter(val => val !== '');

  //search text 'keyfile'
  for (let i = 0; i < outputs.length; i++) {
    if (outputs[i].indexOf('keyfile') > -1) {
      outputs.splice(0, i + 2);
      break;
    }
  }
  let keyFilePath = '';
  for (let i = 0; i < outputs.indexOf('='); i++) {
    keyFilePath += `${outputs[i]}\ `;
  }
  return keyFilePath.slice(0, -10);
}

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
