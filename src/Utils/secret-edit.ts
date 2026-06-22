import { proto } from '../../WAProto/index.js'
import type { WAMessageKey } from '../Types'
import {
	isJidBroadcast,
	isJidGroup,
	isJidStatusBroadcast,
	jidNormalizedUser
} from '../WABinary'
import { aesDecryptGCM, hmacSign } from './crypto'

export type MessageEditContext = {
	editMsgId: string
	editEncKey: Uint8Array
	// Candidate author jids to try in the sign (creator == editor for a self-edit).
	// Whatsmeow uses the message sender's ToNonAD jid AS-IS (LID stays LID, not PN),
	// so the right candidate is usually the edit sender's @lid. We try the available
	// candidates (lid, pn, self) and let AES-GCM's auth tag pick the correct one.
	authorCandidates: string[]
}

// WhatsApp delivers a message edit as a `secretEncryptedMessage`
// (secretEncType MESSAGE_EDIT): the new content is AES-256-GCM encrypted with a
// key derived (HKDF-SHA256 == the poll/event HMAC chain) from the ORIGINAL
// (target) message's messageContextInfo.messageSecret. Verified scheme:
//   key0   = HMAC-SHA256(key=zeros(32), data=messageSecret)
//   sign   = msgId || authorJid || authorJid || "Message Edit" || 0x01
//   decKey = HMAC-SHA256(key=key0, data=sign)
//   aad    = <empty>
//   plaintext = AES-256-GCM(encPayload, decKey, encIv, aad)
// (Ref: whatsmeow msgsecret.go; verified offline against live payloads.)
const MESSAGE_EDIT_LABEL = 'Message Edit'

export function decryptMessageEdit(
	{ encPayload, encIv }: proto.Message.ISecretEncryptedMessage,
	{ editMsgId, editEncKey, authorCandidates }: MessageEditContext
): { message: proto.IMessage; author: string } | undefined {
	const key0 = hmacSign(editEncKey, new Uint8Array(32), 'sha256')
	const aad = Buffer.alloc(0)
	const seen = new Set<string>()
	for (const author of authorCandidates) {
		if (!author || seen.has(author)) {
			continue
		}
		seen.add(author)
		try {
			const sign = Buffer.concat([
				toBinary(editMsgId),
				toBinary(author),
				toBinary(author),
				toBinary(MESSAGE_EDIT_LABEL),
				new Uint8Array([1])
			])
			const decKey = hmacSign(sign, key0, 'sha256')
			const decrypted = aesDecryptGCM(encPayload!, decKey, encIv!, aad)
			return { message: proto.Message.decode(decrypted), author }
		} catch {
			// wrong author -> GCM auth fails; try next candidate
		}
	}
	return undefined

	function toBinary(txt: string) {
		return Buffer.from(txt)
	}
}

// Build the ordered list of candidate author jids to try when decrypting a
// secret-encrypted message edit. WhatsApp signs the edit with the message
// CREATOR's jid AS-IS (LID stays LID); since you can only edit your OWN
// messages, creator == editor. We can't always tell which jid that is up
// front, so we offer every plausible author and let AES-GCM's auth tag select
// the correct one (wrong candidates fail the tag — no false positives).
export function buildEditAuthorCandidates(
	key: Pick<
		WAMessageKey,
		'participant' | 'participantAlt' | 'remoteJid' | 'fromMe'
	>,
	self: { meLid?: string; meId?: string }
): string[] {
	// In a 1:1 chat there is no `participant`; the sender is the chat's
	// remoteJid (used for a peer-edited DM message). Exclude groups/broadcast.
	const remoteJid = key.remoteJid
	const dmPeer =
		remoteJid &&
		!isJidGroup(remoteJid) &&
		!isJidBroadcast(remoteJid) &&
		!isJidStatusBroadcast(remoteJid)
			? jidNormalizedUser(remoteJid)
			: undefined
	const raw = [
		key.participant && jidNormalizedUser(key.participant),
		key.participantAlt && jidNormalizedUser(key.participantAlt),
		// A self-edit's author is our own LID/PN regardless of the stanza's
		// fromMe flag, which a 1:1 self-edit does not reliably set — offer it
		// unconditionally (wrong candidates fail the GCM tag).
		self.meLid,
		self.meId,
		dmPeer
	]
	const seen = new Set<string>()
	const out: string[] = []
	for (const c of raw) {
		if (c && !seen.has(c)) {
			seen.add(c)
			out.push(c)
		}
	}
	return out
}
