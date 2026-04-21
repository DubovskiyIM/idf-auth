// scripts/generate-keys.mjs
// Запускается вручную один раз (или при ротации ключей).
// Вывод вставляется в .env или fly secrets set.
import { generateKeyPair, exportSPKI, exportPKCS8 } from 'jose';

const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
const pub = await exportSPKI(publicKey);
const priv = await exportPKCS8(privateKey);

console.log('=== Put these in .env / Fly secrets ===\n');
console.log('JWT_PUBLIC_KEY_PEM="' + pub.replace(/\n/g, '\\n') + '"\n');
console.log('JWT_PRIVATE_KEY_PEM="' + priv.replace(/\n/g, '\\n') + '"\n');
