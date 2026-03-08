const express = require('express');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Query string parsing via qs — vulnerable to prototype poisoning
app.use((req, res, next) => {
  const queryParams = req.query;
  next();
});

module.exports = app;
