/**
 * Generates a JSON Web Token (JWT).
 *
 * @param {object} options an options object with the following properties:
 *                            privateKey the private key to use in the signature 
 *                            expiresInMinutes the duration (in minutes) of the JWT 
 *                            data the payload to embed within the JWT
 * @return {string} the JWT
 */
const createJwt = ({ privateKey, expiresInMinutes, data = {} }) => {
  // Sign token using HMAC with SHA-256 algorithm
  const header = {
    alg: 'RS256'
  };

  const now = Date.now();
  const expires = new Date(now);
  expires.setMinutes(expires.getMinutes() + expiresInMinutes);

  // iat = issued time, exp = expiration time
  const payload = {
    exp: Math.round(expires.getTime() / 1000),
    iat: Math.round(now / 1000)
  };

  // add user payload
  Object.keys(data).forEach(function (key) {
    payload[key] = data[key];
  });

  const base64Encode = (text, json = true) => {
    const data = json ? JSON.stringify(text) : text;
    return Utilities.base64EncodeWebSafe(data).replace(/=+$/, '');
  };

  const toSign = `${base64Encode(header)}.${base64Encode(payload)}`;
  const signatureBytes = Utilities.computeRsaSha256Signature(
    toSign,
    privateKey
  );
  const signature = base64Encode(signatureBytes, false);

  return `${toSign}.${signature}`;
};
Object.defineProperty(this, 'createJwt', {value: createJwt, enumerable : true});

/**
 * Parses a JSON Web Token (JWT).
 *
 * @param {string} jsonWebToken the encoded JWT
 * @param {string} privateKey the private key used to encode the original JWT
 * @return {void} the decoded JWT
 */
const parseJwt = (jsonWebToken, privateKey) => {
  const [header, payload, signature] = jsonWebToken.split('.');
  const signatureBytes = Utilities.computeHmacSha256Signature(
    `${header}.${payload}`,
    privateKey
  );
  const validSignature = Utilities.base64EncodeWebSafe(signatureBytes);
  if (signature === validSignature.replace(/=+$/, '')) {
    const blob = Utilities.newBlob(
      Utilities.base64Decode(payload)
    ).getDataAsString();
    const { exp, ...data } = JSON.parse(blob);
    if (new Date(exp * 1000) < new Date()) {
      throw new Error('The token has expired');
    }
    Logger.log(data);
  } else {
    Logger.log('🔴', 'Invalid Signature');
  }
};
Object.defineProperty(this, 'parseJwt', {value: parseJwt, enumerable : true});