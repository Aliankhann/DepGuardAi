const _ = require('lodash');
const express = require('express');

const router = express.Router();

router.get('/users', async (req, res) => {
  const users = await db.find({});
  return res.json(_.pick(users, ['id', 'name', 'email']));
});

router.post('/users/merge', async (req, res) => {
  // Merge user-supplied config into defaults — prototype pollution risk
  const merged = _.merge({}, defaultConfig, req.body);
  return res.json(merged);
});

module.exports = router;
