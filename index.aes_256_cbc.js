import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'crypto'

/**
 * Encrypts the text using AES-256-CBC algorithm.
 * @param {string} text utf-8
 * @param {string} key
 * @returns {string} base64
 */
function encrypt(text, key) {
	if (!text || typeof text !== 'string') throw Error('[text] must be a non empty string.')
	if (!key || typeof key !== 'string') throw Error('[key] must be a non empty string.')

	const salt = randomBytes(16)
	const iv = randomBytes(16)
	const key_1 = scryptSync(key, salt, 32)
	const cipher = createCipheriv('aes-256-cbc', key_1, iv)
	cipher.update(text, 'utf-8')
	const encrypted = cipher.final()
	return Buffer.concat([salt, iv, encrypted]).toString('base64')
}

/**
 * Decrypts the text using AES-256-CBC algorithm.
 * @param {string} encryptedText base64
 * @param {string} key
 * @returns {string} utf8
 */
function decrypt(encryptedText, key) {
	if (!encryptedText || typeof encryptedText !== 'string') throw Error('[encryptedText] must be a non empty string.')
	if (!key || typeof key !== 'string') throw Error('[key] must be a non empty string.')

	const buffer = Buffer.from(encryptedText, 'base64')
	const salt = buffer.slice(0, 16)
	const iv = buffer.slice(16, 32)
	const encrypted = buffer.slice(32)
	const key_1 = scryptSync(key, salt, 32)
	const decipher = createDecipheriv('aes-256-cbc', key_1, iv)
	decipher.update(encrypted)
	return decipher.final('utf-8')
}
