const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const secret = process.env.SECRET;

function rmdStr(length) {
  crypto
    .randomBytes(length)
    .toString("base64")
    .slice(0, length)
    .replace(/[^a-zA-Z0-9]/g, "");
}

class ShortURL {
  constructor() {
    this.storage = new Map();
  }

  set(shortStr, token) {
    return this.storage.set(shortStr, token);
  }
  get(shortStr) {
    return this.storage.get(shortStr);
  }
}

const shortURL = new ShortURL();

const generateAccessToken = (payload) => {
  if (!payload) {
    throw new Error("Payload is required for generating token");
  }

  if (typeof payload !== "object") {
    throw new Error("Payload must be an object");
  }

  let token = jwt.sign(payload, secret, { algorithm: "HS256", expiresIn: "2m" });
  const shortId = rmdStr(12);
  shortURL.set(shortId, token);
  return shortId;
};


const verifyToken = () => {
  try {
    let token = shortURL.get(id);
    let decode = jwt.verify(token, secret);
    return {
      status: true,
      payload: decode,
      message: "Email verified successfully",
    };
  } catch (error) {
    return {
      status: false,
      message: error.message,
    };
  }
};

module.exports = {
  generateAccessToken,
  verifyToken,
};
