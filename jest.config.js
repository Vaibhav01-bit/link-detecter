module.exports = {
  testEnvironment: 'jsdom',
  transformIgnorePatterns: [
    'node_modules/(?!(jsdom|parse5|whatwg-url)/)'
  ],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js'],
  preset: null
};
