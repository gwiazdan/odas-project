const PBKDF2_ITERATIONS = 480000;

// Validate RSA private key by attempting to import it
export async function validatePrivateKey(privateKeyPEM: string): Promise<boolean> {
  try {
    const pemContents = privateKeyPEM
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .replace(/\s/g, '');

    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

    await window.crypto.subtle.importKey(
      'pkcs8',
      binaryDer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      false,
      ['decrypt']
    );

    return true;
  } catch (error) {
    console.error('Private key validation failed:', error);
    return false;
  }
}

// Decrypt encrypted private key using password
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

// Core decryption using PBKDF2 + AES-GCM
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

// Import RSA public key from PEM format
async function importPublicKey(pemKey: string): Promise<CryptoKey> {
  const pemContents = pemKey
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');

  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

  return await window.crypto.subtle.importKey(
    'spki',
    binaryDer,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['encrypt']
  );
}

// Import RSA private key from PEM format
async function importPrivateKey(pemKey: string): Promise<CryptoKey> {
  const pemContents = pemKey
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');

  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

  return await window.crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    {
      name: 'RSA-PSS',
      hash: 'SHA-256',
    },
    false,
    ['sign']
  );
}

// Encrypt message with recipient's public key and sign with sender's private key
export async function encryptMessage(
  message: string,
  recipientPublicKeyPEM: string,
  senderPrivateKeyPEM: string
): Promise<{ encryptedMessage: string; signature: string }> {
  const publicKey = await importPublicKey(recipientPublicKeyPEM);
  const privateKey = await importPrivateKey(senderPrivateKeyPEM);

  const messageBuffer = new TextEncoder().encode(message);
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    publicKey,
    messageBuffer
  );

  const encryptedBase64 = btoa(
    String.fromCharCode(...new Uint8Array(encrypted))
  );

  const signature = await window.crypto.subtle.sign(
    {
      name: 'RSA-PSS',
      saltLength: 32,
    },
    privateKey,
    messageBuffer
  );

  const signatureBase64 = btoa(
    String.fromCharCode(...new Uint8Array(signature))
  );

  return {
    encryptedMessage: encryptedBase64,
    signature: signatureBase64,
  };
}

// Decrypt message with recipient's private key
export async function decryptMessage(
  encryptedMessageBase64: string,
  recipientPrivateKeyPEM: string
): Promise<string> {
  const pemContents = recipientPrivateKeyPEM
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');

  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

  const privateKey = await window.crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['decrypt']
  );

  const cleanedBase64 = encryptedMessageBase64.replace(/\s/g, '');
  const encryptedData = Uint8Array.from(
    atob(cleanedBase64),
    c => c.charCodeAt(0)
  );

  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'RSA-OAEP',
    },
    privateKey,
    encryptedData
  );

  return new TextDecoder().decode(decrypted);
}

// Verify message signature with sender's public key
export async function verifySignature(
  message: string,
  signatureBase64: string,
  senderPublicKeyPEM: string
): Promise<boolean> {
  const pemContents = senderPublicKeyPEM
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');

  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

  const publicKey = await window.crypto.subtle.importKey(
    'spki',
    binaryDer,
    {
      name: 'RSA-PSS',
      hash: 'SHA-256',
    },
    false,
    ['verify']
  );

  const cleanedSignature = signatureBase64.replace(/\s/g, '');
  const signature = Uint8Array.from(atob(cleanedSignature), c => c.charCodeAt(0));
  const messageBuffer = new TextEncoder().encode(message);

  return await window.crypto.subtle.verify(
    {
      name: 'RSA-PSS',
      saltLength: 32,
    },
    publicKey,
    signature,
    messageBuffer
  );
}
