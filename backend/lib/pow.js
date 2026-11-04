const crypto = require('crypto');

// difficulty = required number of leading zero BITS in the SHA-256 hash of
// `${nonce}:${solution}`. 4 bits keeps this fast enough for a live demo
// (roughly ~16 tries on average); raise it to make attackers pay more.
function newPuzzle(difficulty = 4) {
  const nonce = crypto.randomBytes(8).toString('hex');
  return { nonce, difficulty };
}

function leadingZeroBits(buf) {
  let bits = 0;
  for (const byte of buf) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    for (let i = 7; i >= 0; i--) {
      if ((byte >> i) & 1) return bits;
      bits++;
    }
  }
  return bits;
}

function verify(nonce, difficulty, solution) {
  const hash = crypto.createHash('sha256').update(`${nonce}:${solution}`).digest();
  return leadingZeroBits(hash) >= difficulty;
}

module.exports = { newPuzzle, verify, leadingZeroBits };
