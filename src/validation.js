export function validate(body, register = false) {
  const data = body && typeof body === 'object' ? body : {};
  const email = typeof data.email === 'string' ? data.email.trim().toLowerCase() : '';
  const password = typeof data.password === 'string' ? data.password : '';
  const errors = {};
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.email = 'Enter a valid email address.';
  if (!password || password.length > 128) errors.password = 'Password is required (maximum 128 characters).';
  const username = typeof data.username === 'string' ? data.username.trim() : '';
  const phone = typeof data.phone === 'string' ? data.phone : '';
  if (register) {
    if (!/^[A-Za-z0-9_]{3,30}$/.test(username)) errors.username = 'Use 3–30 letters, numbers or underscores.';
    if (!/^\d{10}$/.test(phone)) errors.phone = 'Phone must contain exactly 10 digits, with no spaces.';
    if (password.length < 8 || password.length > 128 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) errors.password = 'Use 8–128 characters with at least one letter and one number.';
  }
  return { errors, values: { username, email, phone, password } };
}
