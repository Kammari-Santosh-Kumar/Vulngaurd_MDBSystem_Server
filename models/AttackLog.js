const mongoose = require('mongoose');

const attackLogSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now
  },
  attackType: {
    type: String,
    required: true,
    enum: ['SQL Injection', 'XSS', 'Credential Stuffing', 'Brute Force', 'Path Traversal', 'Command Injection', 'Other']
  },
  sourceIp: {
    type: String,
    required: true
  },
  userAgent: {
    type: String
  },
  targetEndpoint: {
    type: String,
    required: true
  },
  httpMethod: {
    type: String
  },
  payload: {
    type: Object
  },
  headers: {
    type: Object
  },
  severity: {
    type: String,
    enum: ['Critical', 'High', 'Medium', 'Low'],
    default: 'Medium'
  },
  blocked: {
    type: Boolean,
    default: false
  },
  country: {
    type: String
  },
  geolocation: {
    country: String,
    region: String,
    city: String,
    ll: [Number], // [latitude, longitude]
    timezone: String
  },
  notes: {
    type: String
  }
});

// Index for faster queries
attackLogSchema.index({ timestamp: -1 });
attackLogSchema.index({ sourceIp: 1 });
attackLogSchema.index({ attackType: 1 });

module.exports = mongoose.model('AttackLog', attackLogSchema);
