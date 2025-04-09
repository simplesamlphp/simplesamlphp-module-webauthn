// eslint.config.js
const { defineConfig } = require("eslint/config");

module.exports = defineConfig([
    {
        languageOptions: {
            ecmaVersion: 2015,
            sourceType: "module"
        },
        files: [
            "**.js"
        ],
    }
]);
