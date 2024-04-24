import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'crypto'

/**
 * Encrypts the text using AES-256-GCM algorithm.
 * @param {string} text utf-8
 * @param {string} key
 * @returns {string} base64
 */
function encrypt(text, key) {
	if (!text || typeof text !== 'string') throw Error('[text] must be a non empty string.')
	if (!key || typeof key !== 'string') throw Error('[key] must be a non empty string.')

	const iv = randomBytes(12)
	const key_1 = scryptSync(key, '', 32)
	const cipher = createCipheriv('aes-256-gcm', key_1, iv)
	const encrypted = Buffer.concat([cipher.update(text, 'utf-8'), cipher.final()])
	const authTag = cipher.getAuthTag()
	return Buffer.concat([authTag, iv, encrypted]).toString('base64')
}

/**
 * Decrypts the text using AES-256-GCM algorithm.
 * @param {string} encryptedText base64
 * @param {string} key
 * @returns {string} utf8
 */
function decrypt(encryptedText, key) {
	if (!encryptedText || typeof encryptedText !== 'string') throw Error('[encryptedText] must be a non empty string.')
	if (!key || typeof key !== 'string') throw Error('[key] must be a non empty string.')

	const buffer = Buffer.from(encryptedText, 'base64')
	const authTag = buffer.slice(0, 16)
	const iv = buffer.slice(16, 28)
	const encrypted = buffer.slice(28)
	const key_1 = scryptSync(key, '', 32)
	const decipher = createDecipheriv('aes-256-gcm', key_1, iv)
	decipher.setAuthTag(authTag)
	return decipher.update(encrypted) + decipher.final('utf-8')
}
