import { Boom } from '@hapi/boom'
import { jest } from '@jest/globals'
import { EventEmitter } from 'events'
import P from 'pino'
import { type BinaryNode } from '../../WABinary/types'

class FakeWebSocketClient extends EventEmitter {
	isOpen = true
	isClosed = false
	isClosing = false
	sentFrames: Uint8Array[] = []
	onSendHook?: (frame: Uint8Array, ws: FakeWebSocketClient) => void

	async connect() {}

	async close() {
		this.isOpen = false
		this.isClosed = true
	}

	send(data: Uint8Array, cb?: (err?: Error) => void) {
		this.sentFrames.push(data)
		cb?.()
		this.onSendHook?.(data, this)
	}
}

let lastWs: FakeWebSocketClient | null = null

await jest.unstable_mockModule('../../Socket/Client/websocket', () => ({
	WebSocketClient: jest.fn().mockImplementation(() => {
		lastWs = new FakeWebSocketClient()
		return lastWs
	})
}))

const { DEFAULT_CONNECTION_CONFIG } = await import('../../Defaults')
const { DisconnectReason } = await import('../../Types')
const { initAuthCreds } = await import('../../Utils/auth-utils')
const { aesEncryptCTR, derivePairingCodeKey } = await import('../../Utils/crypto')
const { decodeBinaryNode, getBinaryNodeChild } = await import('../../WABinary')
const { makeSocket } = await import('../../Socket/socket')

const logger = P({ level: 'silent' })

function makeInMemoryAuthState() {
	return {
		creds: initAuthCreds(),
		keys: {
			get: async () => ({}),
			set: async () => {}
		} as any
	}
}

function findActiveQueryTag(ws: FakeWebSocketClient): string {
	const tagEvent = ws
		.eventNames()
		.map(String)
		.find(name => name.startsWith('TAG:'))
	if (!tagEvent) {
		throw new Error('Expected active TAG:<id> listener from query()')
	}
	return tagEvent.slice('TAG:'.length)
}

describe('makeSocket.requestPairingCode (C-2 query + 429/timeout safety)', () => {
	afterEach(() => {
		jest.useRealTimers()
		lastWs = null
	})

	it('awaits companion_hello IQ result before mutating creds or emitting creds.update, and encrypts ephemeral key with pairingCode', async () => {
		const state = makeInMemoryAuthState()
		const sock = makeSocket({
			...DEFAULT_CONNECTION_CONFIG,
			logger,
			auth: state
		})
		const ws = lastWs!
		const credsUpdates: unknown[] = []
		sock.ev.on('creds.update', u => credsUpdates.push({ ...u }))

		let credsBeforeReply: { pairingCode?: string; me?: unknown; updatesCount: number } | null = null
		let sentStanza: BinaryNode | null = null

		ws.onSendHook = (rawFrame, client) => {
			// Before Noise finishInit, encodeFrame prepends 4-byte NOISE_WA_HEADER + 3-byte big-endian length
			const payload = Buffer.from(rawFrame.slice(7))
			void decodeBinaryNode(payload).then(decoded => {
				sentStanza = decoded
				const msgId = findActiveQueryTag(client)
				credsBeforeReply = {
					pairingCode: state.creds.pairingCode,
					me: state.creds.me,
					updatesCount: credsUpdates.length
				}
				client.emit(`TAG:${msgId}`, {
					tag: 'iq',
					attrs: {
						from: 's.whatsapp.net',
						type: 'result',
						id: msgId
					},
					content: [
						{
							tag: 'link_code_companion_reg',
							attrs: { stage: 'companion_hello' },
							content: [
								{
									tag: 'link_code_pairing_ref',
									attrs: {},
									content: Buffer.from('server-ref')
								}
							]
						}
					]
				} satisfies BinaryNode)
			})
		}

		const customCode = '1234ABCD'
		const returned = await sock.requestPairingCode('447700900123', customCode)

		expect(returned).toBe(customCode)
		// Crucial C-2 invariant: nothing mutated BEFORE WhatsApp responded with type=result
		expect(credsBeforeReply).toEqual({
			pairingCode: undefined,
			me: undefined,
			updatesCount: 0
		})
		// Committed AFTER query() succeeded
		expect(state.creds.pairingCode).toBe(customCode)
		expect(state.creds.me).toEqual({
			id: '447700900123@s.whatsapp.net',
			name: '~'
		})
		expect(credsUpdates.length).toBe(1)

		// Verify wire stanza + wrapped ephemeral key matches customCode
		expect(sentStanza).not.toBeNull()
		const regNode = getBinaryNodeChild(sentStanza!, 'link_code_companion_reg')
		expect(regNode?.attrs.jid).toBe('447700900123@s.whatsapp.net')
		expect(regNode?.attrs.stage).toBe('companion_hello')
		const wrappedNode = getBinaryNodeChild(regNode, 'link_code_pairing_wrapped_companion_ephemeral_pub')
		const wrapped = Buffer.from(wrappedNode?.content as Uint8Array)
		expect(wrapped.byteLength).toBe(80) // 32 salt + 16 iv + 32 pubkey
		const salt = wrapped.subarray(0, 32)
		const iv = wrapped.subarray(32, 48)
		const ciphered = wrapped.subarray(48, 80)
		const derivedKey = await derivePairingCodeKey(customCode, salt)
		const decryptedPub = aesEncryptCTR(ciphered, derivedKey, iv)
		expect(Buffer.from(decryptedPub)).toEqual(Buffer.from(state.creds.pairingEphemeralKeyPair.public))

		await sock.end(new Error('done'))
	})

	it('throws Boom with err.data === 429 on rate-overlimit IQ error without mutating creds', async () => {
		const state = makeInMemoryAuthState()
		const sock = makeSocket({
			...DEFAULT_CONNECTION_CONFIG,
			logger,
			auth: state
		})
		const ws = lastWs!
		const credsListener = jest.fn()
		sock.ev.on('creds.update', credsListener)

		ws.onSendHook = (_rawFrame, client) => {
			const msgId = findActiveQueryTag(client)
			setImmediate(() => {
				client.emit(`TAG:${msgId}`, {
					tag: 'iq',
					attrs: {
						from: 's.whatsapp.net',
						type: 'error',
						id: msgId
					},
					content: [
						{
							tag: 'error',
							attrs: {
								code: '429',
								text: 'rate-overlimit'
							}
						}
					]
				} satisfies BinaryNode)
			})
		}

		let caught: unknown
		try {
			await sock.requestPairingCode('447700900123', '2345BCDE')
		} catch (err) {
			caught = err
		}

		expect(caught).toBeInstanceOf(Boom)
		expect((caught as Boom).message).toBe('rate-overlimit')
		expect((caught as Boom).data).toBe(429)
		expect(state.creds.pairingCode).toBeUndefined()
		expect(state.creds.me).toBeUndefined()
		expect(credsListener).not.toHaveBeenCalled()

		await sock.end(new Error('done'))
	})

	it('throws timedOut Boom after 20s when companion_hello receives no response, without mutating creds', async () => {
		const state = makeInMemoryAuthState()
		jest.useFakeTimers({ doNotFake: ['nextTick', 'setImmediate'] })

		const sock = makeSocket({
			...DEFAULT_CONNECTION_CONFIG,
			logger,
			auth: state
		})
		const ws = lastWs!
		const credsListener = jest.fn()
		sock.ev.on('creds.update', credsListener)

		ws.onSendHook = () => {
			// Once sendNode fires inside query(iqNode, 20_000), the 20s timer is armed
			setImmediate(() => {
				void jest.advanceTimersByTimeAsync(20_000)
			})
		}

		let caught: unknown
		await sock.requestPairingCode('447700900123', '3456CDEF').catch(err => {
			caught = err
		})

		expect(caught).toBeInstanceOf(Boom)
		expect((caught as Boom).output.statusCode).toBe(DisconnectReason.timedOut)
		expect(state.creds.pairingCode).toBeUndefined()
		expect(state.creds.me).toBeUndefined()
		expect(credsListener).not.toHaveBeenCalled()

		jest.useRealTimers()
		await sock.end(new Error('done'))
	})

	it('rejects customPairingCode whose length !== 8 before sending any stanza', async () => {
		const state = makeInMemoryAuthState()
		const sock = makeSocket({
			...DEFAULT_CONNECTION_CONFIG,
			logger,
			auth: state
		})
		const ws = lastWs!

		await expect(sock.requestPairingCode('447700900123', 'SHORT')).rejects.toThrow(
			'Custom pairing code must be exactly 8 chars'
		)
		expect(ws.sentFrames.length).toBe(0)
		expect(state.creds.pairingCode).toBeUndefined()

		await sock.end(new Error('done'))
	})
})
