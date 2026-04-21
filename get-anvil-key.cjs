const { ethers } = require('ethers');
const mnemonic = "test test test test test test test test test test test junk";
const wallet = ethers.HDNodeWallet.fromPhrase(mnemonic, null, "m/44'/60'/0'/0/0");
console.log('PK:', wallet.privateKey);
console.log('ADDR:', wallet.address);
