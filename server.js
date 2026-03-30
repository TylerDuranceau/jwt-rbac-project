const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); 
const { db, User, Project, Task } = require('./database/setup');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());


/* =========================
   JWT AUTH (REPLACES SESSION)
========================= */
function requireAuth(req, res, next) {
    const header = req.headers.authorization;

    if (!header) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = header.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

/* =========================
   ROLE MIDDLEWARE
========================= */
function requireManager(req, res, next) {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

    if (req.user.role !== 'manager' && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    next();
}

function requireAdmin(req, res, next) {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    next();
}

// Test DB
async function testConnection() {
    try {
        await db.authenticate();
        console.log('Connection to database established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}
testConnection();

/* =========================
   AUTH ROUTES
========================= */

// REGISTER
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role = 'employee' } = req.body;

        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ error: 'User with this email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            name,
            email,
            password: hashedPassword,
            role
        });

        const token = jwt.sign(
            { id: newUser.id, email: newUser.email, role: newUser.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: newUser
        });

    } catch (error) {
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// LOGIN (now uses JWT)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // ✅ JWT instead of session
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({
    message: 'Login successful',
    token,
    user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
    }
});

    } catch (error) {
        res.status(500).json({ error: 'Failed to login' });
    }
});

// LOGOUT (kept simple)
app.post('/api/logout', (req, res) => {
    res.json({ message: 'Logout successful' });
});

/* =========================
   USER ROUTES
========================= */

app.get('/api/users/profile', requireAuth, async (req, res) => {
    const user = await User.findByPk(req.user.id, {
        attributes: ['id', 'name', 'email', 'role']
    });
    res.json(user);
});

// ADMIN ONLY
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    const users = await User.findAll({
        attributes: ['id', 'name', 'email', 'role']
    });
    res.json(users);
});

/* =========================
   PROJECT ROUTES
========================= */

app.get('/api/projects', requireAuth, async (req, res) => {
    const projects = await Project.findAll();
    res.json(projects);
});

app.get('/api/projects/:id', requireAuth, async (req, res) => {
    const project = await Project.findByPk(req.params.id);
    res.json(project);
});

// MANAGER+
app.post('/api/projects', requireAuth, requireManager, async (req, res) => {
    try {
        const { name, description, status = 'active' } = req.body;

        if (!name) {
            return res.status(400).json({ error: 'Project name is required' });
        }

        const newProject = await Project.create({
            name,
            description,
            status,
            managerId: req.user.id
        });

        res.status(201).json(newProject);

    } catch (error) {
        console.error('Error creating project:', error);
        res.status(500).json({ error: 'Failed to create project' });
    }
});

// MANAGER+
app.put('/api/projects/:id', requireAuth, requireManager, async (req, res) => {
    await Project.update(req.body, { where: { id: req.params.id } });
    const updated = await Project.findByPk(req.params.id);
    res.json(updated);
});

// ADMIN ONLY
app.delete('/api/projects/:id', requireAuth, requireAdmin, async (req, res) => {
    await Project.destroy({ where: { id: req.params.id } });
    res.json({ message: 'Project deleted successfully' });
});

/* =========================
   TASK ROUTES
========================= */

app.get('/api/projects/:id/tasks', requireAuth, async (req, res) => {
    const tasks = await Task.findAll({ where: { projectId: req.params.id } });
    res.json(tasks);
});

// MANAGER+
app.post('/api/projects/:id/tasks', requireAuth, requireManager, async (req, res) => {
    const task = await Task.create({
        ...req.body,
        projectId: req.params.id
    });
    res.json(task);
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
    await Task.update(req.body, { where: { id: req.params.id } });
    const updated = await Task.findByPk(req.params.id);
    res.json(updated);
});

// MANAGER+
app.delete('/api/tasks/:id', requireAuth, requireManager, async (req, res) => {
    await Task.destroy({ where: { id: req.params.id } });
    res.json({ message: 'Task deleted successfully' });
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});