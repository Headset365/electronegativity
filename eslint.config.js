import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ignores: ['dist/**', 'test/checks/**', 'test/file_formats/**', 'docs/**', 'node_modules/**']
  },
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.node,
        __: 'readonly'
      }
    },
    rules: {
      'no-console': 'off',
      // checks share a common match(...) signature, not every implementation needs every argument
      'no-unused-vars': ['error', { args: 'none', caughtErrors: 'none' }],
      'indent': ['error', 2, { SwitchCase: 1 }],
      'semi': ['error', 'always']
    }
  },
  {
    files: ['test/**/*.js'],
    languageOptions: {
      globals: globals.mocha
    }
  }
];
