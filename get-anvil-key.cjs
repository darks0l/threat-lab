const { ethers } = require('ethers');
// Load from .keys/ dir (gitignored) — generate with: node get-anvil-key.cjs
const fs = require('fs');
const path = require('path');
const keyFile = path.join(__dirname, '.keys', 'anvil-key.json');
let anvilKey;

if (fs.existsSync(keyFile)) {
  anvilKey = JSON.parse(fs.readFileSync(keyFile, 'utf8')).privateKey;
} else {
  // Fallback: derive from ANVIL_SEED env var (not a real wallet)
  const seed = process.env.ANVIL_SEED;
  if (!seed) {
    console.error('Missing ANVIL_SEED env var and no .keys/anvil-key.json found');
    process.exit(1);
  }
  const wallet = ethers.HDNodeWallet.fromPhrase(seed, null, "m/44'/60'/0'/0/0");
  anvilKey = wallet.privateKey;
}
console.log('PK:', anvilKey);
console.log('ADDR:', new ethers.Wallet(anvilKey).address);
