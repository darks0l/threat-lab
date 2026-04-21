const { ethers } = require('ethers');
// Load from .keys/ dir (gitignored) — generate with: node get-anvil-key.cjs
const fs = require('fs');
const path = require('path');
const keyFile = path.join(__dirname, '.keys', 'anvil-key.json');
let privateKey;

if (fs.existsSync(keyFile)) {
  privateKey = JSON.parse(fs.readFileSync(keyFile, 'utf8')).privateKey;
} else {
  // Fallback: derive from ANVIL_MNEMONIC env var (not a real wallet)
  const mnemonic = process.env.ANVIL_MNEMONIC;
  if (!mnemonic) {
    console.error('Missing ANVIL_MNEMONIC env var and no .keys/anvil-key.json found');
    process.exit(1);
  }
  const wallet = ethers.HDNodeWallet.fromPhrase(mnemonic, null, "m/44'/60'/0'/0/0");
  privateKey = wallet.privateKey;
}
console.log('PK:', privateKey);
console.log('ADDR:', new ethers.Wallet(privateKey).address);
