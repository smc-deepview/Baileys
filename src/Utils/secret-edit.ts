import { proto } from '../../WAProto/index.js'
import { aesDecryptGCM, hmacSign } from './crypto'

export type MessageEditContext = {
	editCreatorJid: string
	editMsgId: string
	editEncKey: Uint8Array
	editorJid: string
}

// WhatsApp can deliver a message edit as a `secretEncryptedMessage`
// (secretEncType MESSAGE_EDIT): the new content is AES-GCM encrypted with a key
// derived from the ORIGINAL (target) message's messageContextInfo.messageSecret,
// mirroring the poll-vote / event-response secret scheme. Upstream Baileys has
// no decryptor for this — this is a deepview addition.
//
// The HMAC `label` is not documented; we try the plausible candidates and let
// AES-GCM's auth tag be the oracle: a wrong label yields the wrong key and the
// GCM tag fails (aesDecryptGCM throws), so only the correct label returns bytes.
export const MESSAGE_EDIT_LABELS = ['Message Edit', 'Edit', 'Comment']

export function decryptMessageEdit(
	{ encPayload, encIv }: proto.Message.ISecretEncryptedMessage,
	{ editCreatorJid, editMsgId, editEncKey, editorJid }: MessageEditContext
): { message: proto.IMessage; label: string } | undefined {
	const key0 = hmacSign(editEncKey, new Uint8Array(32), 'sha256')
	const aad = Buffer.concat([toBinary(editMsgId), Buffer.from([0]), toBinary(editorJid)])
	for (const label of MESSAGE_EDIT_LABELS) {
		try {
			const sign = Buffer.concat([
				toBinary(editMsgId),
				toBinary(editCreatorJid),
				toBinary(editorJid),
				toBinary(label),
				new Uint8Array([1])
			])
			const decKey = hmacSign(sign, key0, 'sha256')
			const decrypted = aesDecryptGCM(encPayload!, decKey, encIv!, aad)
			return { message: proto.Message.decode(decrypted), label }
		} catch {
			// wrong label -> GCM auth fails; try next candidate
		}
	}
	return undefined

	function toBinary(txt: string) {
		return Buffer.from(txt)
	}
}
