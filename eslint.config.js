// Importing global presets and plugins.
const globals = require('globals');

// ESLint main configuration.
module.exports = {
  // Ignoring 'dist' directory globally.
  ignorePatterns: ["dist/**"],

  // Specific settings for JavaScript and JSX files.
  overrides: [
    {
      files: ["**/*.js", "**/*.jsx"],
      parserOptions: {
        ecmaVersion: 2020,
        sourceType: "module",
        ecmaFeatures: {
          jsx: true,
        },
      },
      env: {
        browser: true,
        node: true,
        es2021: true,
      },
      // Importing ESLint recommended rules and other specific plugin rules.
      extends: [
        "eslint:recommended",
        "plugin:react/recommended",
        "plugin:react-hooks/recommended",
      ],
      plugins: [
        "react-hooks",
        "react-refresh"
      ],
      rules: {
        "no-unused-vars": ["error", { varsIgnorePattern: "^[A-Z_]" }],
        "react-hooks/rules-of-hooks": "error", // Checks rules of Hooks
        "react-hooks/exhaustive-deps": "warn", // Checks effect dependencies
        // Custom rule for react-refresh if plugin supports it
        // "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      },
    },
  ],
};
