// Global mocks for Jest
global.File = class File {
  constructor(bits, name, options) {
    this.name = name;
    this.size = bits.length;
    this.type = options.type || '';
    this.bits = bits;
  }
};

global.FileReader = class FileReader {
  constructor() {
    this.result = null;
    this.onload = null;
    this.onerror = null;
  }

  readAsText(file) {
    // Simulate reading file content
    const reader = new Promise((resolve) => {
      setTimeout(() => {
        this.result = Array.from(file.bits).join('');
        if (this.onload) {
          this.onload({ target: { result: this.result } });
        }
        resolve(this.result);
      }, 0);
    });
    return reader;
  }
};

// Mock navigator for service worker
global.navigator = {
  ...global.navigator,
  serviceWorker: {
    register: jest.fn(() => Promise.resolve())
  }
};

// Polyfills for jsdom
global.TextEncoder = require('util').TextEncoder;
global.TextDecoder = require('util').TextDecoder;
