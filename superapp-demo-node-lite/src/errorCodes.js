// All returnCode values used by /user/checkUser, in one place.

export const OK = '0';
export const INVALID_PARAM = '40001';  // body unreadable / not a JSON object / userId missing
export const SIGN_INVALID = '40101';   // signature missing / mismatch / malformed, or identity decrypt failed
export const SIGN_EXPIRED = '40102';   // timestamp outside the allowed window
export const SERVER_ERROR = '50000';   // our own configuration is wrong or an internal error -> fail closed
