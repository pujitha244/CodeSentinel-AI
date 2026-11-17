// sample-projects/sample-javascript/routes/api.js
const express = require('express');
const router = express.Router();
const fileController = require('../controllers/fileController');

// Source of untrusted input: req.query.filepath
router.get('/download', (req, res) => {
  const targetFile = req.query.filepath;
  // Untrusted input forwarded to controller sink without path sanitization
  fileController.serveUserFile(targetFile, res);
});

// TODO: Implement rate limiting on sensitive API endpoints
module.exports = router;
