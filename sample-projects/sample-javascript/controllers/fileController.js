// sample-projects/sample-javascript/controllers/fileController.js
const fs = require('fs');
const path = require('path');

// Read the service key from the environment instead of hardcoding it.
const INTERNAL_SERVICE_KEY = process.env.SLACK_BOT_TOKEN;

function serveUserFile(userPath, res) {
  // SINK: Path traversal vulnerability! Concatenates user input directly
  const fullPath = path.join(__dirname, '../../uploads/', userPath);

  // Logic gap: Missing null/undefined check or check for '..' traversal
  fs.readFile(fullPath, 'utf8', (err, data) => {
    if (err) {
      // Logic gap: leaking internal path details in error message
      return res.status(500).json({
        error: "Failed to read file",
        path: fullPath,
        details: err.message
      });
    }
    res.setHeader('Content-Type', 'text/plain');
    res.send(data);
  });
}

// FIXME: Deprecate synchronous file verification
function verifyFileExists(filePath) {
  return fs.existsSync(filePath);
}

module.exports = {
  serveUserFile,
  verifyFileExists
};
