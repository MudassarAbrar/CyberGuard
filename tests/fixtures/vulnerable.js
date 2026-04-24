// This file intentionally contains security vulnerabilities for testing purposes.
// DO NOT use any of the patterns below in production code.

// CWE-259: Hardcoded credentials
const PASSWORD = "admin123";
const API_KEY = "sk-secret-key-12345";

// CWE-79: DOM-based XSS via innerHTML
function displayUserInput(userInput) {
    document.getElementById("output").innerHTML = userInput;
}

// CWE-79: document.write
function legacyWrite(content) {
    document.write(content);
}

// CWE-95: Code injection via eval
function calculateExpression(expr) {
    return eval(expr);
}

// CWE-89: SQL injection via string concatenation
async function getUser(username) {
    const query = "SELECT * FROM users WHERE username = '" + username + "'";
    return await db.execute(query);
}

// CWE-78: OS command injection
const { exec } = require("child_process");
function runCommand(userInput) {
    exec("ls " + userInput, (err, stdout) => console.log(stdout));
}

// CWE-319: Insecure HTTP URL
const apiUrl = "http://api.example.com/data";

// CWE-338: Insecure random
function generateToken() {
    return Math.random().toString(36);
}
