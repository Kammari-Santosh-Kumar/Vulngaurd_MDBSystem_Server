const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema({
  targetUrl: {
    type: String,
    required: true
  },
  scanType: {
    type: String,
    enum: ['Full', 'Quick', 'Custom'],
    default: 'Quick'
  },
  status: {
    type: String,
    enum: ['Pending', 'Running', 'Completed', 'Failed'],
    default: 'Pending'
  },
  startTime: {
    type: Date,
    default: Date.now
  },
  endTime: {
    type: Date
  },
  totalVulnerabilities: {
    type: Number,
    default: 0
  },
  criticalCount: {
    type: Number,
    default: 0
  },
  highCount: {
    type: Number,
    default: 0
  },
  mediumCount: {
    type: Number,
    default: 0
  },
  lowCount: {
    type: Number,
    default: 0
  },
  scanResults: {
    type: Object
  }
});

module.exports = mongoose.model('Scan', scanSchema);
