const _ = require('lodash');
const express = require('express');

const router = express.Router();

router.get('/users', async (req, res) => {
  const users = await db.find({});
  return res.json(_.pick(users, ['id', 'name', 'email']));
});

module.exports = router;
