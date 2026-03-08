import _ from 'lodash';
import axios from 'axios';

export async function validateSession(token) {
  const payload = _.merge({}, defaultConfig, { token });
  const response = await axios.post('/auth/validate', payload);
  return response.data;
}

export async function fetchUserProfile(userId, redirectUrl) {
  // SSRF risk: redirectUrl is user-controlled and passed to axios
  const response = await axios.get(redirectUrl + '/profile/' + userId);
  return response.data;
}
