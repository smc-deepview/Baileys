import { randomBytes } from 'crypto'
import { proto } from '../../../WAProto/index.js'
import { aesEncryptGCM, hmacSign } from '../../Utils/crypto'
import { decryptMessageEdit } from '../../Utils/secret-edit'

// Round-trip: encrypt an edited message with the SAME secret-message derivation
// the decryptor expects (label 'Message Edit'), then assert decryptMessageEdit
// recovers it and reports the matching label. Proves the crypto plumbing
// (HMAC key derivation + AES-GCM + proto encode/decode) inverts correctly.
// NOTE: validates the *plumbing*, not that 'Message Edit' is WhatsApp's real
// label — that is confirmed empirically on canary against a live edit.

const encryptEdit = (
	plaintext: Uint8Array,
	{
		msgId,
		creatorJid,
		editorJid,
		secret,
		label
	}: { msgId: string; creatorJid: string; editorJid: string; secret: Uint8Array; label: string }
) => {
	const key0 = hmacSign(secret, new Uint8Array(32), 'sha256')
	const sign = Buffer.concat([
		Buffer.from(msgId),
		Buffer.from(creatorJid),
		Buffer.from(editorJid),
		Buffer.from(label),
		new Uint8Array([1])
	])
	const decKey = hmacSign(sign, key0, 'sha256')
	const iv = randomBytes(12)
	const aad = Buffer.from(`${msgId}\u0000${editorJid}`)
	const encPayload = aesEncryptGCM(plaintext, decKey, iv, aad)
	return { encPayload, encIv: iv }
}

const ctx = {
	msgId: 'ORIG123',
	creatorJid: '447441349787@s.whatsapp.net',
	editorJid: '447344116028@s.whatsapp.net',
	secret: randomBytes(32)
}

test('decryptMessageEdit recovers an edit encrypted with the matching scheme', () => {
	const plaintext = proto.Message.encode({ conversation: 'Nice!' }).finish()
	const { encPayload, encIv } = encryptEdit(plaintext, { ...ctx, label: 'Message Edit' })

	const res = decryptMessageEdit(
		{ encPayload, encIv },
		{ editEncKey: ctx.secret, editCreatorJid: ctx.creatorJid, editMsgId: ctx.msgId, editorJid: ctx.editorJid }
	)

	expect(res).toBeDefined()
	expect(res!.label).toBe('Message Edit')
	expect(res!.message.conversation).toBe('Nice!')
})

test('decryptMessageEdit returns undefined when the secret is wrong (GCM auth fails)', () => {
	const plaintext = proto.Message.encode({ conversation: 'Nice!' }).finish()
	const { encPayload, encIv } = encryptEdit(plaintext, { ...ctx, label: 'Message Edit' })

	const res = decryptMessageEdit(
		{ encPayload, encIv },
		{
			editEncKey: randomBytes(32),
			editCreatorJid: ctx.creatorJid,
			editMsgId: ctx.msgId,
			editorJid: ctx.editorJid
		}
	)

	expect(res).toBeUndefined()
})
