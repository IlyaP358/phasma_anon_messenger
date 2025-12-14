const { app, BrowserWindow, Menu } = require('electron');
const path = require('path');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: true,
      spellcheck: true,
      enableRemoteModule: false,
      partition: 'persist:phasma'
    },
    title: 'Phasma Messenger',
    show: false
  });

  Menu.setApplicationMenu(null);

  mainWindow.loadFile('loading.html');

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();

    setTimeout(() => {
      mainWindow.loadURL('https://phasma.secweb.cloud');
    }, 1000);
  });

  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.executeJavaScript(`
      setTimeout(() => {
        const inputs = document.querySelectorAll('input, textarea');
        if (inputs.length > 0) {
          // Убираем readonly если есть
          inputs.forEach(input => {
            input.removeAttribute('readonly');
            input.removeAttribute('disabled');
          });
        }
      }, 100);
    `).catch(err => {
    });
  });

  mainWindow.webContents.on('did-navigate', () => {
    mainWindow.webContents.executeJavaScript(`
      setTimeout(() => {
        const inputs = document.querySelectorAll('input, textarea');
        inputs.forEach(input => {
          input.removeAttribute('readonly');
          input.removeAttribute('disabled');
        });
      }, 100);
    `).catch(err => { });
  });

  mainWindow.webContents.on('did-navigate-in-page', () => {
    mainWindow.webContents.executeJavaScript(`
      setTimeout(() => {
        const inputs = document.querySelectorAll('input, textarea');
        inputs.forEach(input => {
          input.removeAttribute('readonly');
          input.removeAttribute('disabled');
        });
      }, 100);
    `).catch(err => { });
  });

  // mainWindow.webContents.openDevTools();

  mainWindow.on('closed', function () {
    mainWindow = null;
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (!url.startsWith('https://phasma.secweb.cloud')) {
      require('electron').shell.openExternal(url);
      return { action: 'deny' };
    }
    return { action: 'allow' };
  });

  mainWindow.on('page-title-updated', (event) => {
    event.preventDefault();
  });
}

app.on('ready', () => {
  createWindow();

  const { globalShortcut } = require('electron');
  globalShortcut.register('CommandOrControl+R', () => {
    if (mainWindow) {
      mainWindow.webContents.session.clearCache().then(() => {
        mainWindow.reload();
      });
    }
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', function () {
  if (mainWindow === null) {
    createWindow();
  }
});

app.on('browser-window-created', (_, window) => {
  window.webContents.on('before-input-event', (event, input) => {
  });
});
