module.exports = {
    ignorePatterns: ["!/config/webauthn-aaguid.json"],
    parserOptions: {
        ecmaVersion: 2015,
        sourceType: "module"
    },
    overrides: [
        {
            files: ["*.json"],
            extends: ["plugin:jsonc/recommended-with-json"],
            parser: "jsonc-eslint-parser",
        }
    ]
};
