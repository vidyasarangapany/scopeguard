const express = require('express');
const router = express.Router();
const { getLog } = require('../db/database');

router.get('/', (req, res) => {
  try {
    const logs = getLog();
    res.json({ logs });
  } catch (err) {
    console.error('Audit log error:', err);
    res.status(500).json({ error: 'Failed to retrieve audit log' });
  }
});

module.exports = router;
