const _ = require('lodash');

function deepMerge(target, source) {
  return _.merge(target, source);
}

module.exports = { deepMerge };
