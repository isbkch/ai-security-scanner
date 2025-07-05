/**
 * Example JavaScript file with various security vulnerabilities for testing.
 * This file intentionally contains security issues for demonstration purposes.
 */

// Cross-Site Scripting (XSS) vulnerabilities
function updateContent(userInput) {
    // Vulnerable: Direct assignment to innerHTML
    document.getElementById('content').innerHTML = userInput;
}

function displayMessage(message) {
    // Vulnerable: Using eval() with user input
    eval('alert("' + message + '")');
}

function renderTemplate(data) {
    // Vulnerable: Template injection
    const template = `<div>${data.content}</div>`;
    document.body.innerHTML = template;
}

// SQL Injection vulnerabilities (in Node.js context)
function getUserUnsafe(userId) {
    // Vulnerable: String concatenation in SQL query
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    return database.query(query);
}

function searchProductsUnsafe(searchTerm) {
    // Vulnerable: Template literal injection
    const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
    return database.query(query);
}

// Weak cryptography
function generateSessionId() {
    // Vulnerable: Using Math.random() for security-sensitive operations
    return Math.random().toString(36).substring(2);
}

function hashPasswordWeak(password) {
    // Vulnerable: Weak hashing (if using MD5 library)
    return md5(password);
}

// Hardcoded secrets
const API_KEY = "ak_1234567890abcdef1234567890abcdef";
const DATABASE_URL = "mysql://user:password123@localhost/mydb";
const JWT_SECRET = "my-super-secret-jwt-key";

function connectToAPI() {
    // Vulnerable: Hardcoded API credentials
    return fetch('https://api.example.com/data', {
        headers: {
            'Authorization': `Bearer ${API_KEY}`
        }
    });
}

// Insecure deserialization
function loadUserData(jsonData) {
    // Vulnerable: Using eval() to parse JSON
    return eval('(' + jsonData + ')');
}

// Command injection (Node.js)
function backupFile(filename) {
    // Vulnerable: Command injection via exec()
    const { exec } = require('child_process');
    exec(`cp ${filename} /backup/`);
}

// Path traversal
function readUserFile(filename) {
    // Vulnerable: No path validation
    const fs = require('fs');
    return fs.readFileSync(`/uploads/${filename}`, 'utf8');
}

// Prototype pollution
function mergeObjects(target, source) {
    // Vulnerable: No prototype pollution protection
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}

// Regular expression denial of service (ReDoS)
function validateEmail(email) {
    // Vulnerable: Catastrophic backtracking regex
    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    return emailRegex.test(email);
}

// Unsafe redirect
function redirectUser(url) {
    // Vulnerable: Open redirect
    window.location.href = url;
}

// Safe examples for comparison
function updateContentSafe(userInput) {
    // Safe: Using textContent instead of innerHTML
    document.getElementById('content').textContent = userInput;
}

function getUserSafe(userId) {
    // Safe: Parameterized query (example with placeholder)
    const query = 'SELECT * FROM users WHERE id = ?';
    return database.query(query, [userId]);
}

function generateSessionIdSafe() {
    // Safe: Using crypto.getRandomValues()
    const array = new Uint32Array(1);
    crypto.getRandomValues(array);
    return array[0].toString(36);
}

function loadUserDataSafe(jsonData) {
    // Safe: Using JSON.parse()
    return JSON.parse(jsonData);
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        updateContent,
        displayMessage,
        getUserUnsafe,
        generateSessionId,
        loadUserData,
        // Safe versions
        updateContentSafe,
        getUserSafe,
        generateSessionIdSafe,
        loadUserDataSafe
    };
}