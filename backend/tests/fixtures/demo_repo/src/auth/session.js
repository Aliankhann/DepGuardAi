import _ from 'lodash';
import axios from 'axios';

export async function validateSession(token) {
  const payload = _.merge({}, defaultConfig, { token });
  const response = await axios.post('/auth/validate', payload);
  return response.data;
}
