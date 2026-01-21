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
// Uses hybrid encryption (AES-GCM + RSA-OAEP) with gzip compression for large messages
export async function encryptMessage(
  message: string,
  recipientPublicKeyPEM: string,
  senderPrivateKeyPEM: string
): Promise<{ encryptedMessage: string; signature: string }> {
  const publicKey = await importPublicKey(recipientPublicKeyPEM);
  const privateKey = await importPrivateKey(senderPrivateKeyPEM);

  const messageBuffer = new TextEncoder().encode(message);

  const aesKey = await window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );

  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const compressionStream = new CompressionStream('gzip');
  const writer = compressionStream.writable.getWriter();
  writer.write(messageBuffer);
  writer.close();
  const compressedArrayBuffer = await new Response(compressionStream.readable).arrayBuffer();
  const compressedData = new Uint8Array(compressedArrayBuffer);

  const encryptedContent = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    aesKey,
    compressedData
  );

  const exportedKey = await window.crypto.subtle.exportKey('raw', aesKey);

  const encryptedKey = await window.crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    publicKey,
    exportedKey
  );

  const encryptedKeyBytes = new Uint8Array(encryptedKey);
  const ivBytes = new Uint8Array(iv);
  const encryptedContentBytes = new Uint8Array(encryptedContent);

  const combined = new Uint8Array(
    4 + encryptedKeyBytes.length + ivBytes.length + encryptedContentBytes.length
  );

  new DataView(combined.buffer).setUint32(0, encryptedKeyBytes.length, false);
  combined.set(encryptedKeyBytes, 4);
  combined.set(ivBytes, 4 + encryptedKeyBytes.length);
  combined.set(encryptedContentBytes, 4 + encryptedKeyBytes.length + ivBytes.length);

  let binary = '';
  const chunkSize = 8192;
  for (let i = 0; i < combined.length; i += chunkSize) {
    const chunk = combined.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  const encryptedBase64 = btoa(binary);

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
// Supports hybrid encryption (AES-GCM + RSA-OAEP) with gzip compression for large messages
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

  if (encryptedData.length > 4) {
    const keyLength = new DataView(encryptedData.buffer, encryptedData.byteOffset).getUint32(0, false);

    // If keyLength is reasonable (between 256-512 bytes for RSA-2048), assume hybrid encryption
    if (keyLength > 200 && keyLength < 600 && encryptedData.length > keyLength + 16) {
      const encryptedKey = encryptedData.slice(4, 4 + keyLength);
      const iv = encryptedData.slice(4 + keyLength, 4 + keyLength + 12);
      const encryptedContent = encryptedData.slice(4 + keyLength + 12);

      const decryptedKeyBuffer = await window.crypto.subtle.decrypt(
        {
          name: 'RSA-OAEP',
        },
        privateKey,
        encryptedKey
      );

      // Import AES key
      const aesKey = await window.crypto.subtle.importKey(
        'raw',
        decryptedKeyBuffer,
        {
          name: 'AES-GCM',
          length: 256,
        },
        false,
        ['decrypt']
      );

      const decryptedContent = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
        },
        aesKey,
        encryptedContent
      );

      const decompressionStream = new DecompressionStream('gzip');
      const writer = decompressionStream.writable.getWriter();
      writer.write(new Uint8Array(decryptedContent));
      writer.close();
      const decompressedArrayBuffer = await new Response(decompressionStream.readable).arrayBuffer();

      return new TextDecoder().decode(decompressedArrayBuffer);
    }
  }

  // Fallback to direct RSA decryption for old messages
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
