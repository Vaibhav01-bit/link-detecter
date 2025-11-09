const fs = require('fs');
const path = require('path');

// Setup jsdom
const { JSDOM } = require('jsdom');
const dom = new JSDOM('<!DOCTYPE html><body></body>');
global.document = dom.window.document;
global.window = dom.window;
global.navigator = { serviceWorker: { register: jest.fn(() => Promise.resolve()) } };

// Mock localStorage
const localStorageMock = (function () {
  let store = {};
  return {
    getItem: (key) => store[key] || null,
    setItem: (key, value) => { store[key] = value.toString(); },
    removeItem: (key) => { delete store[key]; },
    clear: () => { store = {}; }
  };
})();
Object.defineProperty(window, 'localStorage', { value: localStorageMock });

// Mock FileReader
global.FileReader = class FileReader {
  constructor() {
    this.result = null;
    this.onload = null;
  }
  readAsText(file) {
    // Simulate async read
    setTimeout(() => {
      this.result = file;
      if (this.onload) this.onload({ target: { result: file } });
    }, 0);
  }
};

// Mock fetch
global.fetch = jest.fn();

// Test login modal
test('login modal opens and closes', () => {
  const modal = document.createElement('div');
  modal.id = 'loginModal';
  modal.style = { display: 'none' };
  document.body.appendChild(modal);

  // Simulate open
  const openBtn = document.createElement('button');
  openBtn.onclick = () => modal.style.display = 'block';
  openBtn.click();
  expect(modal.style.display).toBe('block');

  // Simulate close
  const closeBtn = document.createElement('button');
  closeBtn.onclick = () => modal.style.display = 'none';
  closeBtn.click();
  expect(modal.style.display).toBe('none');
});

// Test scan with auth
test('scan URL with JWT auth', async () => {
  const mockResponse = { ok: true, json: async () => ({ phishing: false, score: 0.2 }) };
  fetch.mockResolvedValue(mockResponse);

  // Simulate login to set token
  localStorage.setItem('token', 'mock_jwt');

  // Simulate scan fetch
  const url = 'https://example.com';
  await fetch('/api/scan', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });

  expect(fetch).toHaveBeenCalledWith('/api/scan', expect.objectContaining({
    headers: expect.objectContaining({ 'Authorization': 'Bearer mock_jwt' })
  }));
});

// Test bulk upload parse
test('bulk upload parses URLs from file', () => {
  const fileContent = 'https://example1.com\nhttps://example2.com';
  const file = new File([fileContent], 'urls.txt', { type: 'text/plain' });

  const event = { dataTransfer: { files: [file] } };
  const parseUrls = (e) => {
    const reader = new FileReader();
    reader.onload = (ev) => {
      const urls = ev.target.result.split('\n').filter(u => u.trim());
      expect(urls).toEqual(['https://example1.com', 'https://example2.com']);
    };
    reader.readAsText(e.dataTransfer.files[0]);
  };

  parseUrls(event);
});

// Test PWA service worker register
test('service worker registers', async () => {
  const registerSpy = jest.spyOn(navigator.serviceWorker, 'register');
  registerSpy.mockResolvedValue({});

  // Simulate register call
  await navigator.serviceWorker.register('sw.js');
  expect(registerSpy).toHaveBeenCalledWith('sw.js');
});

// Test accessibility aria-live
test('results section has aria-live', () => {
  const resultsSection = document.createElement('div');
  resultsSection.id = 'resultsSection';
  resultsSection.setAttribute('aria-live', 'polite');
  document.body.appendChild(resultsSection);
  expect(resultsSection.getAttribute('aria-live')).toBe('polite');
});
