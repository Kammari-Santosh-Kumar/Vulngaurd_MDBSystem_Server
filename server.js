const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

const { honeypotMiddleware } = require('./middleware/honeypot');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Make io accessible to routes
app.set('io', io);

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Apply honeypot middleware to all routes
app.use(honeypotMiddleware);

// WebSocket connection handling
io.on('connection', (socket) => {
  console.log('✓ Client connected to WebSocket');
  
  socket.on('disconnect', () => {
    console.log('Client disconnected from WebSocket');
  });
});

// Routes
app.use('/api/scans', require('./routes/scans'));
app.use('/api/vulnerabilities', require('./routes/vulnerabilities'));
app.use('/api/attacks', require('./routes/attacks'));
app.use('/api/honeypot', require('./routes/attacks'));
app.use('/api/reports', require('./routes/reports'));
app.use('/api/scheduled-scans', require('./routes/reports'));

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Vulnerability Management Platform API',
    timestamp: new Date(),
    features: {
      websocket: true,
      scheduling: true,
      emailAlerts: process.env.ENABLE_EMAIL_ALERTS === 'true',
      pdfReports: true,
      geolocation: true
    }
  });
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  console.log('✓ MongoDB Connected Successfully');
  console.log(`✓ Database: ${process.env.MONGODB_URI}`);
})
.catch(err => {
  console.error('✗ MongoDB Connection Error:', err);
  process.exit(1);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    message: 'Internal Server Error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║  🛡️  Vulnerability Management & Honeypot Platform          ║
║                                                            ║
║                                                            ║
║  Server running on port ${PORT}                            ║
║  Environment: ${process.env.NODE_ENV || 'development'}                              ║
║                                                            ║
║                                                            ║
║  ✓ WebSocket Real-time Updates                            ║
║  ✓ PDF Report Generation                                  ║
║  ✓ Email Alerts                                           ║
║  ✓ Scheduled Scans                                        ║
║  ✓ Attack Geolocation                                     ║
║  ✓ Scan Comparison                                        ║
║                                                           ║
║  API Endpoints:                                           ║
║  - GET  /api/health                                       ║
║  - POST /api/scans                                        ║
║  - GET  /api/reports/scan/:id                             ║
║  - POST /api/scheduled-scans                              ║
║  - GET  /api/scans/compare/:id1/:id2                      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;