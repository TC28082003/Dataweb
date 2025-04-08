// server.js
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const { Octokit } = require("@octokit/rest");

const app = express();
const PORT = process.env.PORT || 3000;

// --- Configuration ---
const saltRounds = 10; // For bcrypt password hashing
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = process.env.GITHUB_OWNER;
const GITHUB_REPO = process.env.GITHUB_REPO;
const FRONTEND_URL = process.env.FRONTEND_URL;

if (!GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO || !process.env.SESSION_SECRET || !FRONTEND_URL) {
    console.error("FATAL ERROR: Missing required environment variables (.env file).");
    process.exit(1);
}

const octokit = new Octokit({ auth: GITHUB_TOKEN });

// --- In-Memory Stores (Replace with Database in Production!) ---
const users = {}; // { username: hashedPassword }
const userDataCache = {}; // Simple cache to reduce GitHub reads { username: data }

// --- Middleware ---
app.use(cors({
    origin: FRONTEND_URL, // Allow requests only from your frontend URL
    credentials: true // Allow cookies to be sent/received
}));
app.use(express.json()); // Parse JSON request bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies

// Session Middleware (Use a proper store like connect-redis for production)
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // Don't save sessions for non-logged-in users
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
        httpOnly: true, // Prevent client-side JS access
        maxAge: 24 * 60 * 60 * 1000 // Session expiration (e.g., 1 day)
    }
}));

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.user) {
        return next(); // User is logged in
    }
    res.status(401).json({ message: 'Unauthorized. Please log in.' });
};

// --- GitHub Helper Functions ---

const getUserDataPath = (username) => `data/${username}.json`; // Example file structure

async function fetchUserDataFromGithub(username) {
    console.log(`Fetching data for ${username} from GitHub...`);
    const path = getUserDataPath(username);
    try {
        const response = await octokit.repos.getContent({
            owner: GITHUB_OWNER,
            repo: GITHUB_REPO,
            path: path,
        });
        // Content is base64 encoded
        const content = Buffer.from(response.data.content, 'base64').toString('utf-8');
        console.log(`Data successfully fetched for ${username}.`);
        return JSON.parse(content);
    } catch (error) {
        if (error.status === 404) {
            console.log(`No data file found for ${username} in GitHub. Returning empty object.`);
            return {}; // File doesn't exist, return empty data structure
        }
        console.error(`Error fetching data for ${username} from GitHub:`, error.message);
        throw new Error('Could not retrieve user data.'); // Rethrow for caller to handle
    }
}

async function saveUserDataToGithub(username, data) {
    console.log(`Attempting to save data for ${username} to GitHub...`);
    const path = getUserDataPath(username);
    const content = Buffer.from(JSON.stringify(data, null, 2)).toString('base64'); // Pretty print JSON
    let currentSha = undefined;

    // Try to get the current file SHA (needed for updates)
    try {
        const { data: fileData } = await octokit.repos.getContent({
            owner: GITHUB_OWNER,
            repo: GITHUB_REPO,
            path: path,
        });
        currentSha = fileData.sha;
        console.log(`File exists for ${username}, SHA: ${currentSha}. Will update.`);
    } catch (error) {
        if (error.status === 404) {
            console.log(`File does not exist for ${username}. Will create.`);
        } else {
            console.error(`Error checking file existence for ${username}:`, error.message);
            throw new Error('Could not check existing user data file.');
        }
    }

    // Create or update the file
    try {
        await octokit.repos.createOrUpdateFileContents({
            owner: GITHUB_OWNER,
            repo: GITHUB_REPO,
            path: path,
            message: `Update data for user ${username}`, // Commit message
            content: content,
            sha: currentSha, // Include SHA if updating, omit if creating
            committer: { // Optional: Identify the committer
                name: 'MyApp Bot',
                email: 'bot@example.com'
            },
            author: { // Optional: Identify the author
                name: 'MyApp Bot',
                email: 'bot@example.com'
            }
        });
        console.log(`Data successfully saved for ${username} to ${path}`);
        userDataCache[username] = data; // Update cache on successful save
    } catch (error) {
        console.error(`Error saving data for ${username} to GitHub:`, error.message);
         if (error.response && error.response.data) {
            console.error("GitHub API Response:", error.response.data);
        }
        throw new Error('Could not save user data.');
    }
}

// --- API Routes ---

// Authentication Routes
app.post('/api/auth/signup', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password || password.length < 4) {
        return res.status(400).json({ message: 'Username and password (min 4 chars) are required.' });
    }
    if (users[username]) {
        return res.status(409).json({ message: 'Username already exists.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        users[username] = hashedPassword; // Store in our *insecure* memory store
        console.log(`User ${username} registered.`);
         // Optionally: Create an empty data file on GitHub upon signup
         await saveUserDataToGithub(username, { /* initial empty data structure */ });
        res.status(201).json({ message: 'User registered successfully.' });
    } catch (error) {
        console.error("Signup Error:", error);
        res.status(500).json({ message: 'Internal server error during signup.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    const hashedPassword = users[username];
    if (!hashedPassword) {
        return res.status(401).json({ message: 'Invalid username or password.' });
    }

    try {
        const match = await bcrypt.compare(password, hashedPassword);
        if (match) {
            // Passwords match - Set up session
            req.session.user = { username: username }; // Store user info in session
            console.log(`User ${username} logged in. Session ID: ${req.session.id}`);
            res.status(200).json({ message: 'Login successful.', username: username });
        } else {
            res.status(401).json({ message: 'Invalid username or password.' });
        }
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: 'Internal server error during login.' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    const username = req.session.user?.username;
    req.session.destroy(err => {
        if (err) {
            console.error("Logout Error:", err);
            return res.status(500).json({ message: 'Could not log out.' });
        }
        console.log(`User ${username || '(unknown)'} logged out.`);
        // Clear the cookie on the client side
        res.clearCookie('connect.sid'); // 'connect.sid' is the default session cookie name
        res.status(200).json({ message: 'Logged out successfully.' });
    });
});

// Optional: Check login status
app.get('/api/auth/status', (req, res) => {
    if (req.session && req.session.user) {
        res.status(200).json({ isLoggedIn: true, username: req.session.user.username });
    } else {
        res.status(200).json({ isLoggedIn: false });
    }
});


// User Data Routes (Protected)
app.get('/api/user/data', isAuthenticated, async (req, res) => {
    const username = req.session.user.username;
    try {
         // Optional: Check cache first
         // if (userDataCache[username]) {
         //     console.log(`Returning cached data for ${username}`);
         //     return res.status(200).json(userDataCache[username]);
         // }
        const data = await fetchUserDataFromGithub(username);
        userDataCache[username] = data; // Update cache
        res.status(200).json(data);
    } catch (error) {
        res.status(500).json({ message: error.message || 'Failed to fetch user data.' });
    }
});

app.post('/api/user/data', isAuthenticated, async (req, res) => {
    const username = req.session.user.username;
    const data = req.body; // Assume frontend sends the complete data structure

    if (!data) {
        return res.status(400).json({ message: 'No data provided.' });
    }

    try {
        await saveUserDataToGithub(username, data);
        res.status(200).json({ message: 'Data saved successfully.' });
    } catch (error) {
        res.status(500).json({ message: error.message || 'Failed to save user data.' });
    }
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
    console.log(`Expecting frontend requests from: ${FRONTEND_URL}`);
});