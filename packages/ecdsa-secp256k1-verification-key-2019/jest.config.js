const packagesToTransform = ['base58-universal'].join('|')

module.exports = {
  // testEnvironment: 'node',
  transformIgnorePatterns: [`[/\\\\]node_modules[/\\\\](?!(${packagesToTransform})).+\\.(js|jsx)$`],
  globals: {
    'ts-jest': {
      tsconfig: './tsconfig.test.json',
    },
  },
}
