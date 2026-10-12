// Cripto simétrica para segredos guardados no Postgres (hoje: token do FortiGate).
// AES-256-GCM autentica além de cifrar: um token adulterado no banco falha na
// decifragem em vez de virar uma string corrompida silenciosa.
//
// A chave vem de FORTIGATE_KEY. Aceita 64 caracteres hex (32 bytes) ou uma
// passphrase qualquer, que é reduzida a 32 bytes por SHA-256. Sem a env, não dá
// para cifrar nem decifrar: erro explícito, nunca grava em claro "para não falhar".
const crypto = require('node:crypto');

const IV_BYTES = 12;
const ALGO = 'aes-256-gcm';

function key() {
  const raw = process.env.FORTIGATE_KEY || '';
  if (!raw) throw Object.assign(new Error('FORTIGATE_KEY não configurada: não é possível cifrar/decifrar o token do FortiGate.'), { status: 500 });
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, 'hex');
  return crypto.createHash('sha256').update(raw, 'utf8').digest();
}

function encrypt(plain) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGO, key(), iv);
  const ciphertext = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64')
  };
}

function decrypt({ ciphertext, iv, tag }) {
  const decipher = crypto.createDecipheriv(ALGO, key(), Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64')), decipher.final()]).toString('utf8');
}

module.exports = { encrypt, decrypt, hasKey: () => Boolean(process.env.FORTIGATE_KEY) };
