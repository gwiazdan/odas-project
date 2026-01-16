const PBKDF2_ITERATIONS = 480000;

export async function decryptPrivateKey(
  encryptedPrivateKeyBase64: string,
  saltBase64: string,
  password: string,
): Promise<string> {

  const encryptedData = Uint8Array.from(atob(encryptedPrivateKeyBase64), c => c.charCodeAt(0));
  const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));


  const nonce = encryptedData.slice(0, 12);
  const ciphertext = encryptedData.slice(12);


  return decryptPrivateKeyBrowser(salt, nonce, ciphertext, password);
}

async function decryptPrivateKeyBrowser(
  salt: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  password: string,
): Promise<string> {
  const passwordBuffer = new TextEncoder().encode(password);

  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveBits'],
  );

  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    baseKey,
    256,
  );

  const key = await window.crypto.subtle.importKey(
    'raw',
    derivedBits,
    'AES-GCM',
    false,
    ['decrypt'],
  );

  try {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce as BufferSource,
      },
      key,
      ciphertext as BufferSource,
    );

    return new TextDecoder().decode(decrypted);
  } catch {
    throw new Error('Failed to decrypt private key - invalid password or corrupted data');
  }
}
