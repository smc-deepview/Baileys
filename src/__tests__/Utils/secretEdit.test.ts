import { randomBytes } from 'crypto'
import { proto } from '../../../WAProto/index.js'
import { aesEncryptGCM, hmacSign } from '../../Utils/crypto'
import {
	buildEditAuthorCandidates,
	decryptMessageEdit
} from '../../Utils/secret-edit'

// Encrypt an edit with the verified MESSAGE_EDIT scheme (creator == editor ==
// author, label "Message Edit", EMPTY AAD), then assert decryptMessageEdit
// recovers it and picks the right author from the candidate list. Scheme was
// confirmed offline against live payloads (whatsmeow msgsecret.go).
const encryptEdit = (
	plaintext: Uint8Array,
	{ msgId, author, secret }: { msgId: string; author: string; secret: Uint8Array }
) => {
	const key0 = hmacSign(secret, new Uint8Array(32), 'sha256')
	const sign = Buffer.concat([
		Buffer.from(msgId),
		Buffer.from(author),
		Buffer.from(author),
		Buffer.from('Message Edit'),
		new Uint8Array([1])
	])
	const decKey = hmacSign(sign, key0, 'sha256')
	const iv = randomBytes(12)
	const encPayload = aesEncryptGCM(plaintext, decKey, iv, Buffer.alloc(0))
	return { encPayload, encIv: iv }
}

const ctx = {
	msgId: 'ORIG123',
	author: '208426307182752@lid',
	secret: randomBytes(32)
}

test('decryptMessageEdit recovers an edit and selects the right author candidate', () => {
	const plaintext = proto.Message.encode({ conversation: 'Nice!' }).finish()
	const { encPayload, encIv } = encryptEdit(plaintext, ctx)

	const res = decryptMessageEdit(
		{ encPayload, encIv },
		{
			editMsgId: ctx.msgId,
			editEncKey: ctx.secret,
			authorCandidates: ['447736318413@s.whatsapp.net', ctx.author]
		}
	)

	expect(res).toBeDefined()
	expect(res!.author).toBe(ctx.author)
	expect(res!.message.conversation).toBe('Nice!')
})

test('decryptMessageEdit returns undefined when no candidate matches', () => {
	const plaintext = proto.Message.encode({ conversation: 'Nice!' }).finish()
	const { encPayload, encIv } = encryptEdit(plaintext, ctx)

	const res = decryptMessageEdit(
		{ encPayload, encIv },
		{
			editMsgId: ctx.msgId,
			editEncKey: ctx.secret,
			authorCandidates: ['nobody@lid']
		}
	)

	expect(res).toBeUndefined()
})

describe('buildEditAuthorCandidates', () => {
	const self = {
		meLid: '184894751785188@lid',
		meId: '447736318413@s.whatsapp.net'
	}

	// Wall A: a 1:1 self-edit stanza has no `participant` and does NOT reliably
	// carry fromMe=true, so the only correct author (our own LID) must still be
	// offered. Gating self jids on fromMe leaves the candidate list empty.
	test('offers our own LID for a 1:1 self-edit even when the stanza is not fromMe', () => {
		const candidates = buildEditAuthorCandidates(
			{ remoteJid: '240492449116339@lid', fromMe: false },
			self
		)
		expect(candidates).toContain(self.meLid)
	})

	// DMs have no `participant`; for a peer-edited 1:1 message the author is the
	// chat's remoteJid.
	test('offers the DM peer as author for a 1:1 peer-edit', () => {
		const candidates = buildEditAuthorCandidates(
			{ remoteJid: '208426307182752@lid', fromMe: false },
			self
		)
		expect(candidates).toContain('208426307182752@lid')
	})

	test('keeps the group sender (participant) as a candidate', () => {
		const candidates = buildEditAuthorCandidates(
			{
				remoteJid: '120363253644374358@g.us',
				participant: '184894751785188@lid',
				fromMe: true
			},
			self
		)
		expect(candidates).toContain('184894751785188@lid')
	})

	test('never offers a group jid as an author candidate', () => {
		const candidates = buildEditAuthorCandidates(
			{
				remoteJid: '120363253644374358@g.us',
				participant: '156457337131068@lid',
				fromMe: true
			},
			self
		)
		expect(candidates).not.toContain('120363253644374358@g.us')
	})
})
