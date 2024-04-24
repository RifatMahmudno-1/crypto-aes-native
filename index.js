/**
 * Derives a 256-bit key from the provided key string using SHA-256.
 * @param {string} key
 * @returns {Promise<CryptoKey>} The derived AES-GCM key
 */
async function deriveKey(key) {
	const encodedKey = new TextEncoder().encode(key)
	const hash = await globalThis.crypto.subtle.digest('SHA-256', encodedKey)
	return globalThis.crypto.subtle.importKey('raw', hash, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

/**
 * Encrypts the text using AES-GCM algorithm using Web Crypto API.
 * @param {string} text utf-8
 * @param {string} key
 * @returns {Promise<string>} base64url
 */
async function encrypt(text, key) {
	if (!text || typeof text !== 'string') throw new Error('[text] must be a non-empty string.')
	if (!key || typeof key !== 'string') throw new Error('[key] must be a non-empty string.')

	const key_1 = await deriveKey(key)
	const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
	const encrypted = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key_1, new TextEncoder().encode(text))

	const encryptedArray = new Uint8Array(encrypted)
	const buffer = new Uint8Array(encryptedArray.length + iv.length)
	buffer.set(iv, 0)
	buffer.set(encryptedArray, iv.length)
	return btoa(String.fromCharCode.apply(null, buffer)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/**
 * Decrypts the text using AES-GCM algorithm using Web Crypto API.
 * @param {string} encryptedText base64url
 * @param {string} key
 * @returns {Promise<string>} utf8
 */
async function decrypt(encryptedText, key) {
	if (!encryptedText || typeof encryptedText !== 'string') throw new Error('[encryptedText] must be a non-empty string.')
	if (!key || typeof key !== 'string') throw new Error('[key] must be a non-empty string.')

	const key_1 = await deriveKey(key)
	const buffer = new Uint8Array(
		atob(encryptedText.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (encryptedText.length % 4)) % 4))
			.split('')
			.map(char => char.charCodeAt(0))
	)
	const iv = buffer.slice(0, 12)
	const encryptedData = buffer.slice(12)

	const decrypted = await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key_1, encryptedData)
	return new TextDecoder().decode(decrypted)
}
