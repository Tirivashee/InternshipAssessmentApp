// tailwind.config.js
const { nextui } = require("@nextui-org/react");

module.exports = {
    content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
    theme: {
        extend: {},
    },
    plugins: [nextui()],
};
