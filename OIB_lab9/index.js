const button = document.getElementById("rand");
const hash = document.getElementById("hash");
const codeMessage = document.getElementById("codeMessage");
const encode = document.getElementById("encode");
const decode = document.getElementById("decode");
const pack = document.getElementById("pack");
const signa = document.getElementById("signa");

button.addEventListener("click", () => {
  const array = new Uint8Array(1);
  for (let i = 0; i < 5; i++) {
    console.log(crypto.getRandomValues(array));
  }
});

async function digestMessage(message) {
  const encoder = new TextEncoder(); 
  const data = encoder.encode(message);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hash));                     
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join(''); 
  console.log(hashHex);
  return hash;
}

hash.addEventListener("click", () => {
  digestMessage(codeMessage.value).then((digestBuffer) => console.log(digestBuffer));
});

let decryptKey;
let byteMessage;
const encryptDecryptParams = { name: "AES-GCM", iv: crypto.getRandomValues(new Uint8Array(16))};

async function encodeMessage() {
  const params = { name: 'AES-GCM', length: 128 };
  const keyUsages = ['encrypt', 'decrypt'];
  const key = await window.crypto.subtle.generateKey(params, true, keyUsages);
  console.log(key);
  decryptKey = key;
  const originalPlaintext = new TextEncoder().encode(codeMessage.value);
  const ciphertext = await crypto.subtle.encrypt(encryptDecryptParams, key, originalPlaintext);
  byteMessage = ciphertext;
  console.log(ciphertext);
}
encode.addEventListener("click", encodeMessage);

async function decodeMessage() {
  const decryptedPlaintext = await crypto.subtle.decrypt(encryptDecryptParams, decryptKey, byteMessage);
  console.log(new TextDecoder().decode(decryptedPlaintext));
}
decode.addEventListener("click", decodeMessage);Ы

async function WrapKey() {
  const keyFormat = "raw";
  const extractable = true;
  const wrappingKeyAlgoIdentifier = "AES-KW";
  const wrappingKeyUsages = ["wrapKey", "unwrapKey"];
  const wrappingKeyParams = { name: wrappingKeyAlgoIdentifier, length: 256 };
  const keyAlgoIdentifier = 'AES-GCM';
  const keyUsages = ['encrypt'];
  const keyParams = { name: keyAlgoIdentifier,length: 256};
  const wrappingKey = await crypto.subtle.generateKey(wrappingKeyParams,
  extractable, wrappingKeyUsages);
  console.log(wrappingKey);
  const key = await crypto.subtle.generateKey(keyParams, extractable, keyUsages);
  console.log(key);
  const wrappedKey = await crypto.subtle.wrapKey(keyFormat, key, 
  wrappingKey, wrappingKeyAlgoIdentifier);
  console.log(wrappedKey);
  const unwrappedKey = await crypto.subtle.unwrapKey(keyFormat, wrappedKey, 
  wrappingKey, wrappingKeyParams, keyParams, extractable, keyUsages);
  console.log(unwrappedKey);
}
pack.addEventListener("click", WrapKey);

async function sign () {
  const keyParams = { name: "ECDSA", namedCurve: "P-256",};
  const keyUsages = ["sign", "verify"];
  const { publicKey, privateKey } = await crypto.subtle.generateKey(keyParams, true, keyUsages);
  const message = new TextEncoder().encode("Mes to sign");
  const signParams = { name: "ECDSA", hash: "SHA-256",};
  const signature = await crypto.subtle.sign(signParams, privateKey, message);
  const verified = await crypto.subtle.verify(signParams, publicKey, signature, message);
  console.log(signParams, publicKey, message);
  console.log(verified);
};
signa.addEventListener("click", () => { sign();});