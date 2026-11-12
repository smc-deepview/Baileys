import { Boom } from '@hapi/boom'
import { randomBytes } from 'crypto'
import { URL } from 'url'
import { promisify } from 'util'
import { proto } from '../../WAProto/index.js'
import {
	DEF_CALLBACK_PREFIX,
	DEF_TAG_PREFIX,
	INITIAL_PREKEY_COUNT,
	MIN_PREKEY_COUNT,
	NOISE_WA_HEADER,
	PROCESSABLE_HISTORY_TYPES,
	TimeMs,
	UPLOAD_TIMEOUT
} from '../Defaults'
import {
	type LIDMapping,
	type MediaConnInfo,
	type NewChatMessageCapInfo,
	QueryIds,
	ReachoutTimelockEnforcementType,
	type ReachoutTimelockState,
	type SocketConfig
} from '../Types'
import { DisconnectReason, XWAPaths } from '../Types'
import {
	addTransactionCapability,
	aesEncryptCTR,
	bindWaitForConnectionUpdate,
	buildPairingQRData,
	bytesToCrockford,
	configureSuccessfulPairing,
	Curve,
	DEF_MEDIA_HOST,
	derivePairingCodeKey,
	generateLoginNode,
	generateMdTagPrefix,
	generateRegistrationNode,
	getCodeFromWSError,
	getCompanionPlatformId,
	getErrorCodeFromStreamError,
	getNextPreKeysNode,
	makeEventBuffer,
	makeNoiseHandler,
	pairCodeKeepAliveMs,
	promiseTimeout,
	signedKeyPair,
	xmppSignedPreKey
} from '../Utils'
import { makeMutex } from '../Utils/make-mutex'
import {
	assertNodeErrorFree,
	type BinaryNode,
	binaryNodeToString,
	encodeBinaryNode,
	getAllBinaryNodeChildren,
	getBinaryNodeChild,
	getBinaryNodeChildren,
	isLidUser,
	jidDecode,
	jidEncode,
	S_WHATSAPP_NET
} from '../WABinary'
import { BinaryInfo } from '../WAM/BinaryInfo.js'
import { USyncQuery, USyncUser } from '../WAUSync/'
import { WebSocketClient } from './Client'
import { executeWMexQuery } from './mex.js'

/**
 * Connects to WA servers and performs:
 * - simple queries (no retry mechanism, wait for connection establishment)
 * - listen to messages and emit events
 * - query phone connection
 */

export const makeSocket = (config: SocketConfig) => {
	const {
		waWebSocketUrl,
		connectTimeoutMs,
		logger,
		keepAliveIntervalMs,
		browser,
		auth: authState,
		printQRInTerminal,
		defaultQueryTimeoutMs,
		transactionOpts,
		qrTimeout,
		makeSignalRepository
	} = config

	const publicWAMBuffer = new BinaryInfo()

	let serverTimeOffsetMs = 0

	const uqTagId = generateMdTagPrefix()
	const generateMessageTag = () => `${uqTagId}${epoch++}`

	if (printQRInTerminal) {
		logger.warn(
			{},
			'⚠️ The printQRInTerminal option has been deprecated. You will no longer receive QR codes in the terminal automatically. Please listen to the connection.update event yourself and handle the QR your way. You can remove this message by removing this opttion. This message will be removed in a future version.'
		)
	}

	if (browser[1].toLocaleLowerCase().includes('android')) {
		logger.warn(
			'⚠️ Using the Android browser is experimental and may lead to unexpected behavior. Use at your own risk.'
		)
	}

	const syncDisabled =
		PROCESSABLE_HISTORY_TYPES.map(syncType => config.shouldSyncHistoryMessage({ syncType })).filter(x => x === false)
			.length === PROCESSABLE_HISTORY_TYPES.length
	if (syncDisabled) {
		logger.warn(
			'⚠️ DANGER: DISABLING ALL SYNC BY shouldSyncHistoryMsg PREVENTS BAILEYS FROM ACCESSING INITIAL LID MAPPINGS, LEADING TO INSTABILIY AND SESSION ERRORS'
		)
	}

	const url = typeof waWebSocketUrl === 'string' ? new URL(waWebSocketUrl) : waWebSocketUrl

	if (config.mobile || url.protocol === 'tcp:') {
		throw new Boom('Mobile API is not supported anymore', { statusCode: DisconnectReason.loggedOut })
	}

	if (url.protocol === 'wss' && authState?.creds?.routingInfo) {
		url.searchParams.append('ED', authState.creds.routingInfo.toString('base64url'))
	}

	/** ephemeral key pair used to encrypt/decrypt communication. Unique for each connection */
	const ephemeralKeyPair = Curve.generateKeyPair()
	/** WA noise protocol wrapper */
	const noise = makeNoiseHandler({
		keyPair: ephemeralKeyPair,
		NOISE_HEADER: NOISE_WA_HEADER,
		logger,
		routingInfo: authState?.creds?.routingInfo
	})

	const ws = new WebSocketClient(url, config)

	ws.connect()

	const sendPromise = promisify(ws.send)
	/** send a raw buffer */
	const sendRawMessage = async (data: Uint8Array | Buffer) => {
		if (!ws.isOpen) {
			throw new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed })
		}

		const bytes = noise.encodeFrame(data)
		await promiseTimeout<void>(connectTimeoutMs, async (resolve, reject) => {
			try {
				await sendPromise.call(ws, bytes)
				resolve()
			} catch (error) {
				reject(error)
			}
		})
	}

	/** send a binary node */
	const sendNode = (frame: BinaryNode) => {
		if (logger.level === 'trace') {
			logger.trace({ xml: binaryNodeToString(frame), msg: 'xml send' })
		}

		const buff = encodeBinaryNode(frame)
		return sendRawMessage(buff)
	}

	/**
	 * Wait for a message with a certain tag to be received
	 * @param msgId the message tag to await
	 * @param timeoutMs timeout after which the promise will reject
	 */
	const waitForMessage = async <T>(msgId: string, timeoutMs = defaultQueryTimeoutMs) => {
		let onRecv: ((data: T) => void) | undefined
		let onErr: ((err: Error) => void) | undefined
		try {
			const result = await promiseTimeout<T>(timeoutMs, (resolve, reject) => {
				onRecv = data => {
					resolve(data)
				}

				onErr = err => {
					reject(
						err ||
							new Boom('Connection Closed', {
								statusCode: DisconnectReason.connectionClosed
							})
					)
				}

				ws.on(`TAG:${msgId}`, onRecv)
				ws.on('close', onErr)
				ws.on('error', onErr)

				return () => reject(new Boom('Query Cancelled'))
			})
			return result
		} catch (error) {
			// Catch timeout and return undefined instead of throwing
			if (error instanceof Boom && error.output?.statusCode === DisconnectReason.timedOut) {
				logger?.warn?.({ msgId }, 'timed out waiting for message')
				return undefined
			}

			throw error
		} finally {
			if (onRecv) ws.off(`TAG:${msgId}`, onRecv)
			if (onErr) {
				ws.off('close', onErr)
				ws.off('error', onErr)
			}
		}
	}

	/** send a query, and wait for its response. auto-generates message ID if not provided */
	const query = async (node: BinaryNode, timeoutMs?: number) => {
		if (!node.attrs.id) {
			node.attrs.id = generateMessageTag()
		}

		const msgId = node.attrs.id

		const result = await promiseTimeout<any>(timeoutMs, async (resolve, reject) => {
			const result = waitForMessage(msgId, timeoutMs).catch(reject)
			sendNode(node)
				.then(async () => resolve(await result))
				.catch(reject)
		})

		if (result && 'tag' in result) {
			assertNodeErrorFree(result)
		}

		return result
	}

	// --- media_conn machinery ---
	//
	// `mediaHost` is the per-socket CDN hostname WhatsApp returned in the
	// most recent `media_conn` IQ. Lives on the BASE socket so every
	// layer above (chats.ts app-state sync, messages-send.ts uploads,
	// process-message.ts history sync) can route their downloads /
	// uploads through the correct shard for this connection. Pre-Stage-11
	// it lived in messages-send.ts which made it invisible to chats.ts
	// (lower in the layering) — app-state external-blob downloads kept
	// hitting `mmg.whatsapp.net` even when the socket was assigned a
	// different host, producing 400s under `extractSyncdPatches`.
	let mediaConn: Promise<MediaConnInfo> | undefined
	let mediaHost: string = DEF_MEDIA_HOST
	const mediaConnMutex = makeMutex()

	/**
	 * Safely await the cached `mediaConn`. A previously-stored rejected
	 * promise would otherwise rethrow forever and poison every caller;
	 * we catch, clear the slot, and let the caller fall through to a
	 * fresh fetch.
	 */
	const safeAwaitMediaConn = async (): Promise<MediaConnInfo | undefined> => {
		if (!mediaConn) return undefined
		try {
			return await mediaConn
		} catch (err) {
			logger.warn?.({ err }, 'previous media_conn fetch failed, will retry')
			mediaConn = undefined
			return undefined
		}
	}

	const refreshMediaConn = async (forceGet = false): Promise<MediaConnInfo> => {
		const cached = await safeAwaitMediaConn()
		if (cached && !forceGet && new Date().getTime() - cached.fetchDate.getTime() <= cached.ttl * 1000) {
			return cached
		}

		return mediaConnMutex.mutex(async () => {
			// Re-check inside the lock: another caller may have refreshed.
			const after = await safeAwaitMediaConn()
			if (after && !forceGet && new Date().getTime() - after.fetchDate.getTime() <= after.ttl * 1000) {
				return after
			}

			mediaConn = (async () => {
				const result = await query({
					tag: 'iq',
					attrs: {
						type: 'set',
						xmlns: 'w:m',
						to: S_WHATSAPP_NET
					},
					content: [{ tag: 'media_conn', attrs: {} }]
				})
				const mediaConnNode = getBinaryNodeChild(result, 'media_conn')!
				const node: MediaConnInfo = {
					hosts: getBinaryNodeChildren(mediaConnNode, 'host').map(({ attrs }) => ({
						hostname: attrs.hostname!,
						maxContentLengthBytes: +attrs.maxContentLengthBytes!
					})),
					auth: mediaConnNode.attrs.auth!,
					ttl: +mediaConnNode.attrs.ttl!,
					fetchDate: new Date()
				}
				logger.debug('fetched media conn')
				if (node.hosts[0]) {
					mediaHost = node.hosts[0].hostname
				}

				return node
			})()

			return mediaConn
		})
	}

	const getMediaHost = () => mediaHost

	// Validate current key-bundle on server; on failure, trigger pre-key upload and rethrow
	const digestKeyBundle = async (): Promise<void> => {
		const res = await query({
			tag: 'iq',
			attrs: { to: S_WHATSAPP_NET, type: 'get', xmlns: 'encrypt' },
			content: [{ tag: 'digest', attrs: {} }]
		})
		const digestNode = getBinaryNodeChild(res, 'digest')
		if (!digestNode) {
			await uploadPreKeys()
			throw new Error('encrypt/get digest returned no digest node')
		}
	}

	// Rotate our signed pre-key on server; on failure, run digest as fallback and rethrow
	const rotateSignedPreKey = async (): Promise<void> => {
		const newId = (creds.signedPreKey.keyId || 0) + 1
		const skey = await signedKeyPair(creds.signedIdentityKey, newId)
		await query({
			tag: 'iq',
			attrs: { to: S_WHATSAPP_NET, type: 'set', xmlns: 'encrypt' },
			content: [
				{
					tag: 'rotate',
					attrs: {},
					content: [xmppSignedPreKey(skey)]
				}
			]
		})
		// Persist new signed pre-key in creds
		ev.emit('creds.update', { signedPreKey: skey })
	}

	const executeUSyncQuery = async (usyncQuery: USyncQuery) => {
		if (usyncQuery.protocols.length === 0) {
			throw new Boom('USyncQuery must have at least one protocol')
		}

		// todo: validate users, throw WARNING on no valid users
		// variable below has only validated users
		const validUsers = usyncQuery.users

		const userNodes = validUsers.map(user => {
			return {
				tag: 'user',
				attrs: {
					jid: !user.phone ? user.id : undefined
				},
				content: usyncQuery.protocols.map(a => a.getUserElement(user)).filter(a => a !== null)
			} as BinaryNode
		})

		const listNode: BinaryNode = {
			tag: 'list',
			attrs: {},
			content: userNodes
		}

		const queryNode: BinaryNode = {
			tag: 'query',
			attrs: {},
			content: usyncQuery.protocols.map(a => a.getQueryElement())
		}
		const iq = {
			tag: 'iq',
			attrs: {
				to: S_WHATSAPP_NET,
				type: 'get',
				xmlns: 'usync'
			},
			content: [
				{
					tag: 'usync',
					attrs: {
						context: usyncQuery.context,
						mode: usyncQuery.mode,
						sid: generateMessageTag(),
						last: 'true',
						index: '0'
					},
					content: [queryNode, listNode]
				}
			]
		}

		const result = await query(iq)

		return usyncQuery.parseUSyncQueryResult(result)
	}

	const onWhatsApp = async (...phoneNumber: string[]) => {
		let usyncQuery = new USyncQuery()

		let contactEnabled = false
		for (const jid of phoneNumber) {
			if (isLidUser(jid)) {
				logger?.warn('LIDs are not supported with onWhatsApp')
				continue
			} else {
				if (!contactEnabled) {
					contactEnabled = true
					usyncQuery = usyncQuery.withContactProtocol()
				}

				const phone = `+${jid.replace('+', '').split('@')[0]?.split(':')[0]}`
				usyncQuery.withUser(new USyncUser().withPhone(phone))
			}
		}

		if (usyncQuery.users.length === 0) {
			return [] // return early without forcing an empty query
		}

		const results = await executeUSyncQuery(usyncQuery)

		if (results) {
			return results.list.filter(a => !!a.contact).map(({ contact, id }) => ({ jid: id, exists: contact as boolean }))
		}
	}

	const pnFromLIDUSync = async (jids: string[]): Promise<LIDMapping[] | undefined> => {
		const usyncQuery = new USyncQuery().withLIDProtocol().withContext('background')

		for (const jid of jids) {
			if (isLidUser(jid)) {
				logger?.warn('LID user found in LID fetch call')
				continue
			} else {
				usyncQuery.withUser(new USyncUser().withId(jid))
			}
		}

		if (usyncQuery.users.length === 0) {
			return [] // return early without forcing an empty query
		}

		const results = await executeUSyncQuery(usyncQuery)

		if (results) {
			return results.list.filter(a => !!a.lid).map(({ lid, id }) => ({ pn: id, lid: lid as string }))
		}

		return []
	}

	const ev = makeEventBuffer(logger)

	const { creds } = authState
	// add transaction capability
	const keys = addTransactionCapability(authState.keys, logger, transactionOpts)
	const signalRepository = makeSignalRepository({ creds, keys }, logger, pnFromLIDUSync)

	let lastDateRecv: Date
	let epoch = 1
	let keepAliveReq: NodeJS.Timeout
	let qrTimer: NodeJS.Timeout
	let closed = false

	const socketEndHandlers: Array<(error: Error | undefined) => void | Promise<void>> = []

	/** log & process any unexpected errors */
	const onUnexpectedError = (err: Error | Boom, msg: string) => {
		logger.error({ err }, `unexpected error in '${msg}'`)
	}

	/** await the next incoming message */
	const awaitNextMessage = async <T>(sendMsg?: Uint8Array) => {
		if (!ws.isOpen) {
			throw new Boom('Connection Closed', {
				statusCode: DisconnectReason.connectionClosed
			})
		}

		let onOpen: (data: T) => void
		let onClose: (err: Error) => void

		const result = promiseTimeout<T>(connectTimeoutMs, (resolve, reject) => {
			onOpen = resolve
			onClose = mapWebSocketError(reject)
			ws.on('frame', onOpen)
			ws.on('close', onClose)
			ws.on('error', onClose)
		}).finally(() => {
			ws.off('frame', onOpen)
			ws.off('close', onClose)
			ws.off('error', onClose)
		})

		if (sendMsg) {
			sendRawMessage(sendMsg).catch(onClose!)
		}

		return result
	}

	/** connection handshake */
	const validateConnection = async () => {
		let helloMsg: proto.IHandshakeMessage = {
			clientHello: { ephemeral: ephemeralKeyPair.public }
		}
		helloMsg = proto.HandshakeMessage.fromObject(helloMsg)

		logger.info({ browser, helloMsg }, 'connected to WA')

		const init = proto.HandshakeMessage.encode(helloMsg).finish()

		const result = await awaitNextMessage<Uint8Array>(init)
		const handshake = proto.HandshakeMessage.decode(result)

		logger.trace({ handshake }, 'handshake recv from WA')

		const keyEnc = noise.processHandshake(handshake, creds.noiseKey)

		let node: proto.IClientPayload
		if (!creds.me) {
			node = generateRegistrationNode(creds, config)
			logger.info({ node }, 'not logged in, attempting registration...')
		} else {
			node = generateLoginNode(creds.me.id, config)
			logger.info({ node }, 'logging in...')
		}

		const payloadEnc = noise.encrypt(proto.ClientPayload.encode(node).finish())
		await sendRawMessage(
			proto.HandshakeMessage.encode({
				clientFinish: {
					static: keyEnc,
					payload: payloadEnc
				}
			}).finish()
		)
		await noise.finishInit()
		startKeepAliveRequest()
	}

	const getAvailablePreKeysOnServer = async () => {
		const result = await query({
			tag: 'iq',
			attrs: {
				id: generateMessageTag(),
				xmlns: 'encrypt',
				type: 'get',
				to: S_WHATSAPP_NET
			},
			content: [{ tag: 'count', attrs: {} }]
		})
		const countChild = getBinaryNodeChild(result, 'count')!
		return +countChild.attrs.value!
	}

	// WAWeb has no time throttle here; the server drives uploads via PreKeyLow notifications.
	let uploadPreKeysPromise: Promise<void> | null = null

	/** generates and uploads a set of pre-keys to the server */
	const uploadPreKeys = async (count = MIN_PREKEY_COUNT) => {
		if (uploadPreKeysPromise) {
			logger.debug('Pre-key upload already in progress, waiting for completion')
			await uploadPreKeysPromise
			return
		}

		const uploadLogic = async (retryCount: number): Promise<void> => {
			logger.info({ count, retryCount }, 'uploading pre-keys')

			// Generate and save pre-keys atomically (prevents ID collisions on retry)
			const node = await keys.transaction(async () => {
				logger.debug({ requestedCount: count }, 'generating pre-keys with requested count')
				const { update, node } = await getNextPreKeysNode({ creds, keys }, count)
				// Update credentials immediately to prevent duplicate IDs on retry
				ev.emit('creds.update', update)
				return node
			}, creds?.me?.id || 'upload-pre-keys')

			// Upload to server (outside transaction, can fail without affecting local keys)
			try {
				await query(node)
				logger.info({ count }, 'uploaded pre-keys successfully')
			} catch (uploadError) {
				logger.error({ uploadError: (uploadError as Error).toString(), count }, 'Failed to upload pre-keys to server')

				// Recurse into uploadLogic; calling uploadPreKeys would await its own in-flight promise.
				if (retryCount < 3) {
					const backoffDelay = Math.min(1000 * Math.pow(2, retryCount), 10000)
					logger.info(`Retrying pre-key upload in ${backoffDelay}ms`)
					await new Promise(resolve => setTimeout(resolve, backoffDelay))
					return uploadLogic(retryCount + 1)
				}

				throw uploadError
			}
		}

		// Add timeout protection
		uploadPreKeysPromise = Promise.race([
			uploadLogic(0),
			new Promise<void>((_, reject) =>
				setTimeout(() => reject(new Boom('Pre-key upload timeout', { statusCode: 408 })), UPLOAD_TIMEOUT)
			)
		])

		try {
			await uploadPreKeysPromise
		} finally {
			uploadPreKeysPromise = null
		}
	}

	const verifyCurrentPreKeyExists = async () => {
		const currentPreKeyId = creds.nextPreKeyId - 1
		if (currentPreKeyId <= 0) {
			return { exists: false, currentPreKeyId: 0 }
		}

		const preKeys = await keys.get('pre-key', [currentPreKeyId.toString()])
		const exists = !!preKeys[currentPreKeyId.toString()]

		return { exists, currentPreKeyId }
	}

	const uploadPreKeysToServerIfRequired = async () => {
		try {
			let count = 0
			const preKeyCount = await getAvailablePreKeysOnServer()
			if (preKeyCount === 0) count = INITIAL_PREKEY_COUNT
			else count = MIN_PREKEY_COUNT
			const { exists: currentPreKeyExists, currentPreKeyId } = await verifyCurrentPreKeyExists()

			logger.info(`${preKeyCount} pre-keys found on server`)
			logger.info(`Current prekey ID: ${currentPreKeyId}, exists in storage: ${currentPreKeyExists}`)

			const lowServerCount = preKeyCount <= count
			const missingCurrentPreKey = !currentPreKeyExists && currentPreKeyId > 0

			const shouldUpload = lowServerCount || missingCurrentPreKey

			if (shouldUpload) {
				const reasons = []
				if (lowServerCount) reasons.push(`server count low (${preKeyCount})`)
				if (missingCurrentPreKey) reasons.push(`current prekey ${currentPreKeyId} missing from storage`)

				logger.info(`Uploading PreKeys due to: ${reasons.join(', ')}`)
				await uploadPreKeys(count)
			} else {
				logger.info(`PreKey validation passed - Server: ${preKeyCount}, Current prekey ${currentPreKeyId} exists`)
			}
		} catch (error) {
			logger.error({ error }, 'Failed to check/upload pre-keys during initialization')
			// Don't throw - allow connection to continue even if pre-key check fails
		}
	}

	const onMessageReceived = async (data: Buffer) => {
		await noise.decodeFrame(data, frame => {
			// reset ping timeout
			lastDateRecv = new Date()

			let anyTriggered = false

			anyTriggered = ws.emit('frame', frame)
			// if it's a binary node
			if (!(frame instanceof Uint8Array)) {
				const msgId = frame.attrs.id

				if (logger.level === 'trace') {
					logger.trace({ xml: binaryNodeToString(frame), msg: 'recv xml' })
				}

				/* Check if this is a response to a message we sent */
				anyTriggered = ws.emit(`${DEF_TAG_PREFIX}${msgId}`, frame) || anyTriggered
				/* Check if this is a response to a message we are expecting */
				const l0 = frame.tag
				const l1 = frame.attrs || {}
				const l2 = Array.isArray(frame.content) ? frame.content[0]?.tag : ''

				for (const key of Object.keys(l1)) {
					anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}:${l1[key]},${l2}`, frame) || anyTriggered
					anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}:${l1[key]}`, frame) || anyTriggered
					anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}`, frame) || anyTriggered
				}

				anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},,${l2}`, frame) || anyTriggered
				anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0}`, frame) || anyTriggered

				if (!anyTriggered && logger.level === 'debug') {
					logger.debug({ unhandled: true, msgId, fromMe: false, frame }, 'communication recv')
				}
			}
		})
	}

	const end = async (error: Error | undefined) => {
		if (closed) {
			logger.trace({ trace: error?.stack }, 'connection already closed')
			return
		}

		closed = true
		logger.info({ trace: error?.stack }, error ? 'connection errored' : 'connection closed')

		clearInterval(keepAliveReq)
		clearTimeout(qrTimer)

		ws.removeAllListeners('close')
		ws.removeAllListeners('open')
		ws.removeAllListeners('message')

		signalRepository.close?.()

		if (!ws.isClosed && !ws.isClosing) {
			try {
				await ws.close()
			} catch {}
		}

		for (const handler of socketEndHandlers) {
			try {
				await handler(error)
			} catch (err) {
				logger.error({ err }, 'error in socket end handler')
			}
		}

		ev.emit('connection.update', {
			connection: 'close',
			lastDisconnect: {
				error,
				date: new Date()
			}
		})
		ev.removeAllListeners('connection.update')
		ev.destroy()
	}

	const waitForSocketOpen = async () => {
		if (ws.isOpen) {
			return
		}

		if (ws.isClosed || ws.isClosing) {
			throw new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed })
		}

		let onOpen: () => void
		let onClose: (err: Error) => void
		await new Promise((resolve, reject) => {
			onOpen = () => resolve(undefined)
			onClose = mapWebSocketError(reject)
			ws.on('open', onOpen)
			ws.on('close', onClose)
			ws.on('error', onClose)
		}).finally(() => {
			ws.off('open', onOpen)
			ws.off('close', onClose)
			ws.off('error', onClose)
		})
	}

	const startKeepAliveRequest = () =>
		(keepAliveReq = setInterval(() => {
			if (!lastDateRecv) {
				lastDateRecv = new Date()
			}

			const diff = Date.now() - lastDateRecv.getTime()
			/*
				check if it's been a suspicious amount of time since the server responded with our last seen
				it could be that the network is down
			*/
			if (diff > keepAliveIntervalMs + 5000) {
				void end(new Boom('Connection was lost', { statusCode: DisconnectReason.connectionLost }))
			} else if (ws.isOpen) {
				// if its all good, send a keep alive request
				query({
					tag: 'iq',
					attrs: {
						id: generateMessageTag(),
						to: S_WHATSAPP_NET,
						type: 'get',
						xmlns: 'w:p'
					},
					content: [{ tag: 'ping', attrs: {} }]
				}).catch(err => {
					logger.error({ trace: err.stack }, 'error in sending keep alive')
				})
			} else {
				logger.warn('keep alive called when WS not open')
			}
		}, keepAliveIntervalMs))
	/** i have no idea why this exists. pls enlighten me */
	const sendPassiveIq = (tag: 'passive' | 'active') =>
		query({
			tag: 'iq',
			attrs: {
				to: S_WHATSAPP_NET,
				xmlns: 'passive',
				type: 'set'
			},
			content: [{ tag, attrs: {} }]
		})

	/** logout & invalidate connection */
	const logout = async (msg?: string) => {
		const jid = authState.creds.me?.id
		if (jid) {
			await sendNode({
				tag: 'iq',
				attrs: {
					to: S_WHATSAPP_NET,
					type: 'set',
					id: generateMessageTag(),
					xmlns: 'md'
				},
				content: [
					{
						tag: 'remove-companion-device',
						attrs: {
							jid,
							reason: 'user_initiated'
						}
					}
				]
			})
		}

		void end(new Boom(msg || 'Intentional Logout', { statusCode: DisconnectReason.loggedOut }))
	}

	const requestPairingCode = async (phoneNumber: string, customPairingCode?: string): Promise<string> => {
		const pairingCode = customPairingCode ?? bytesToCrockford(randomBytes(5))

		if (customPairingCode && customPairingCode?.length !== 8) {
			throw new Error('Custom pairing code must be exactly 8 chars')
		}

		const jid = jidEncode(phoneNumber, 's.whatsapp.net')
		const iqNode: BinaryNode = {
			tag: 'iq',
			attrs: {
				to: S_WHATSAPP_NET,
				type: 'set',
				id: generateMessageTag(),
				xmlns: 'md'
			},
			content: [
				{
					tag: 'link_code_companion_reg',
					attrs: {
						jid,
						stage: 'companion_hello',

						should_show_push_notification: 'true'
					},
					content: [
						{
							tag: 'link_code_pairing_wrapped_companion_ephemeral_pub',
							attrs: {},
							content: await generatePairingKey(pairingCode)
						},
						{
							tag: 'companion_server_auth_key_pub',
							attrs: {},
							content: authState.creds.noiseKey.public
						},
						{
							tag: 'companion_platform_id',
							attrs: {},
							content: getCompanionPlatformId(browser)
						},
						{
							tag: 'companion_platform_display',
							attrs: {},
							content: `${browser[1]} (${browser[0]})`
						},
						{
							tag: 'link_code_pairing_nonce',
							attrs: {},
							content: '0'
						}
					]
				}
			]
		}

		const res = await query(iqNode, 20_000)
		if (!res) {
			throw new Boom('Timed out waiting for companion_hello response', {
				statusCode: DisconnectReason.timedOut
			})
		}

		authState.creds.pairingCode = pairingCode
		authState.creds.me = {
			id: jid,
			name: '~'
		}
		ev.emit('creds.update', authState.creds)
		return pairingCode
	}

	async function generatePairingKey(pairingCode: string) {
		const salt = randomBytes(32)
		const randomIv = randomBytes(16)
		const key = await derivePairingCodeKey(pairingCode, salt)
		const ciphered = aesEncryptCTR(authState.creds.pairingEphemeralKeyPair.public, key, randomIv)
		return Buffer.concat([salt, randomIv, ciphered])
	}

	const sendWAMBuffer = (wamBuffer: Buffer) => {
		return query({
			tag: 'iq',
			attrs: {
				to: S_WHATSAPP_NET,
				id: generateMessageTag(),
				xmlns: 'w:stats'
			},
			content: [
				{
					tag: 'add',
					attrs: { t: Math.round(Date.now() / 1000) + '' },
					content: wamBuffer
				}
			]
		})
	}

	ws.on('message', onMessageReceived)

	ws.on('open', async () => {
		try {
			await validateConnection()
		} catch (err: any) {
			logger.error({ err }, 'error in validating connection')
			void end(err)
		}
	})
	ws.on('error', mapWebSocketError(end))
	ws.on('close', () => void end(new Boom('Connection Terminated', { statusCode: DisconnectReason.connectionClosed })))
	// the server terminated the connection
	ws.on(
		'CB:xmlstreamend',
		() => void end(new Boom('Connection Terminated by Server', { statusCode: DisconnectReason.connectionClosed }))
	)
	// QR gen
	ws.on('CB:iq,type:set,pair-device', async (stanza: BinaryNode) => {
		const iq: BinaryNode = {
			tag: 'iq',
			attrs: {
				to: S_WHATSAPP_NET,
				type: 'result',
				id: stanza.attrs.id!
			}
		}
		await sendNode(iq)

		const pairDeviceNode = getBinaryNodeChild(stanza, 'pair-device')
		const refNodes = getBinaryNodeChildren(pairDeviceNode, 'ref')
		const noiseKeyB64 = Buffer.from(creds.noiseKey.public).toString('base64')
		const identityKeyB64 = Buffer.from(creds.signedIdentityKey.public).toString('base64')
		const advB64 = creds.advSecretKey

		// Max lifetime for a pair-CODE ("link with phone number") session. The
		// QR-ref cycle (scan flow) exhausts at ~2:40, but the code stays valid
		// server-side longer, so keep the socket alive up to this cap.
		const PAIRING_CODE_MAX_LIFETIME_MS = 5 * 60 * 1000
		const pairStartedAt = Date.now()
		let qrMs = qrTimeout || 60_000 // time to let a QR live
		const genPairQR = () => {
			if (!ws.isOpen) {
				return
			}

			const refNode = refNodes.shift()
			if (!refNode) {
				// QR refs exhausted. In the pair-CODE flow the user types a code
				// rather than scanning, and WhatsApp keeps it valid beyond the QR-ref
				// cycle — keep the socket alive up to the code's max lifetime instead
				// of ending here.
				const keepAliveMs = pairCodeKeepAliveMs(
					!!creds.pairingCode,
					pairStartedAt,
					Date.now(),
					PAIRING_CODE_MAX_LIFETIME_MS
				)
				if (keepAliveMs !== null) {
					qrTimer = setTimeout(() => {
						void end(new Boom('pairing code lifetime exceeded', { statusCode: DisconnectReason.timedOut }))
					}, keepAliveMs)
					return
				}
				void end(new Boom('QR refs attempts ended', { statusCode: DisconnectReason.timedOut }))
				return
			}

			const ref = (refNode.content as Buffer).toString('utf-8')
			const qr = buildPairingQRData(ref, noiseKeyB64, identityKeyB64, advB64, browser)

			ev.emit('connection.update', { qr })

			qrTimer = setTimeout(genPairQR, qrMs)
			qrMs = qrTimeout || 20_000 // shorter subsequent qrs
		}

		genPairQR()
	})
	// device paired for the first time
	// if device pairs successfully, the server asks to restart the connection
	ws.on('CB:iq,,pair-success', async (stanza: BinaryNode) => {
		logger.debug('pair success recv')
		try {
			updateServerTimeOffset(stanza)
			const { reply, creds: updatedCreds } = configureSuccessfulPairing(stanza, creds)

			logger.info(
				{ me: updatedCreds.me, platform: updatedCreds.platform },
				'pairing configured successfully, expect to restart the connection...'
			)

			ev.emit('creds.update', updatedCreds)
			ev.emit('connection.update', { isNewLogin: true, qr: undefined })

			await sendNode(reply)
			void sendUnifiedSession()
		} catch (error: any) {
			logger.info({ trace: error.stack }, 'error in pairing')
			void end(error)
		}
	})
	// login complete
	ws.on('CB:success', async (node: BinaryNode) => {
		try {
			updateServerTimeOffset(node)
			await uploadPreKeysToServerIfRequired()
			await sendPassiveIq('active')

			// After successful login, validate our key-bundle against server
			try {
				await digestKeyBundle()
			} catch (e) {
				logger.warn({ e }, 'failed to run digest after login')
			}

			// Pre-fetch the media_conn host once the socket is ready so
			// later downloads (app-state external blobs, history sync,
			// media messages) hit the CDN shard WhatsApp assigned this
			// connection instead of the hardcoded `mmg.whatsapp.net`
			// fallback. The result is cached + TTL-managed inside
			// `refreshMediaConn` itself, so subsequent calls are no-ops
			// until the TTL expires. Failure here is non-fatal — uploads
			// already re-fetch on demand, and downloads fall back to
			// `DEF_MEDIA_HOST` (so we end up where we were before this
			// fix), just with a structured warning the operator can
			// alert on.
			try {
				await refreshMediaConn()
			} catch (err) {
				logger.warn({ err }, 'failed to pre-fetch media_conn on socket open')
			}
		} catch (err) {
			logger.warn({ err }, 'failed to send initial passive iq')
		}

		logger.info('opened connection to WA')
		clearTimeout(qrTimer) // will never happen in all likelyhood -- but just in case WA sends success on first try

		ev.emit('creds.update', { me: { ...authState.creds.me!, lid: node.attrs.lid } })

		ev.emit('connection.update', { connection: 'open' })
		void sendUnifiedSession()

		if (node.attrs.lid && authState.creds.me?.id) {
			const myLID = node.attrs.lid
			process.nextTick(async () => {
				try {
					const myPN = authState.creds.me!.id

					// Store our own LID-PN mapping
					await signalRepository.lidMapping.storeLIDPNMappings([{ lid: myLID, pn: myPN }])

					// Create device list for our own user (needed for bulk migration)
					const { user, device } = jidDecode(myPN)!
					await authState.keys.set({
						'device-list': {
							[user]: [device?.toString() || '0']
						}
					})

					// migrate our own session
					await signalRepository.migrateSession(myPN, myLID)

					logger.info({ myPN, myLID }, 'Own LID session created successfully')
				} catch (error) {
					logger.error({ error, lid: myLID }, 'Failed to create own LID session')
				}
			})
		}
	})

	ws.on('CB:stream:error', (node: BinaryNode) => {
		const [reasonNode] = getAllBinaryNodeChildren(node)
		logger.error({ reasonNode, fullErrorNode: node }, 'stream errored out')

		const { reason, statusCode } = getErrorCodeFromStreamError(node)

		void end(new Boom(`Stream Errored (${reason})`, { statusCode, data: reasonNode || node }))
	})
	// stream fail, possible logout
	ws.on('CB:failure', (node: BinaryNode) => {
		const reason = +(node.attrs.reason || 500)
		void end(new Boom('Connection Failure', { statusCode: reason, data: node.attrs }))
	})

	ws.on('CB:ib,,downgrade_webclient', () => {
		void end(new Boom('Multi-device beta not joined', { statusCode: DisconnectReason.multideviceMismatch }))
	})

	ws.on('CB:ib,,offline_preview', async (node: BinaryNode) => {
		logger.info('offline preview received', JSON.stringify(node))
		await sendNode({
			tag: 'ib',
			attrs: {},
			content: [{ tag: 'offline_batch', attrs: { count: '100' } }]
		})
	})

	ws.on('CB:ib,,edge_routing', (node: BinaryNode) => {
		const edgeRoutingNode = getBinaryNodeChild(node, 'edge_routing')
		const routingInfo = getBinaryNodeChild(edgeRoutingNode, 'routing_info')
		if (routingInfo?.content) {
			authState.creds.routingInfo = Buffer.from(routingInfo?.content as Uint8Array)
			ev.emit('creds.update', authState.creds)
		}
	})

	let didStartBuffer = false
	process.nextTick(() => {
		if (creds.me?.id) {
			// start buffering important events
			// if we're logged in
			ev.buffer()
			didStartBuffer = true
		}

		ev.emit('connection.update', { connection: 'connecting', receivedPendingNotifications: false, qr: undefined })
	})

	// called when all offline notifs are handled
	ws.on('CB:ib,,offline', (node: BinaryNode) => {
		const child = getBinaryNodeChild(node, 'offline')
		const offlineNotifs = +(child?.attrs.count || 0)

		logger.info(`handled ${offlineNotifs} offline messages/notifications`)
		if (didStartBuffer) {
			ev.flush()
			logger.trace('flushed events for initial buffer')
		}

		ev.emit('connection.update', { receivedPendingNotifications: true })
	})

	// update credentials when required
	ev.on('creds.update', update => {
		const name = update.me?.name
		// if name has just been received
		if (creds.me?.name !== name) {
			logger.debug({ name }, 'updated pushName')
			sendNode({
				tag: 'presence',
				attrs: { name: name! }
			}).catch(err => {
				logger.warn({ trace: err.stack }, 'error in sending presence update on name change')
			})
		}

		Object.assign(creds, update)
	})

	const updateServerTimeOffset = ({ attrs }: BinaryNode) => {
		const tValue = attrs?.t
		if (!tValue) {
			return
		}

		const parsed = Number(tValue)
		if (Number.isNaN(parsed) || parsed <= 0) {
			return
		}

		const localMs = Date.now()
		serverTimeOffsetMs = parsed * 1000 - localMs
		logger.debug({ offset: serverTimeOffsetMs }, 'calculated server time offset')
	}

	const getUnifiedSessionId = () => {
		const offsetMs = 3 * TimeMs.Day
		const now = Date.now() + serverTimeOffsetMs
		const id = (now + offsetMs) % TimeMs.Week
		return id.toString()
	}

	const sendUnifiedSession = async () => {
		if (!ws.isOpen) {
			return
		}

		const node = {
			tag: 'ib',
			attrs: {},
			content: [
				{
					tag: 'unified_session',
					attrs: {
						id: getUnifiedSessionId()
					}
				}
			]
		}

		try {
			await sendNode(node)
		} catch (error) {
			logger.debug({ error }, 'failed to send unified_session telemetry')
		}
	}

	const registerSocketEndHandler = (handler: (error: Error | undefined) => void | Promise<void>) => {
		socketEndHandlers.push(handler)
	}

	/**
	 * Fetches your account's standing when it comes to restrictions.
	 * @returns Returns the state of the restrictions.
	 */
	const fetchAccountReachoutTimelock = async () => {
		const queryResult = await executeWMexQuery<{
			is_active?: boolean
			time_enforcement_ends?: string
			enforcement_type: ReachoutTimelockEnforcementType
		}>({}, QueryIds.REACHOUT_TIMELOCK, XWAPaths.xwa2_fetch_account_reachout_timelock, query, generateMessageTag)
		const result: ReachoutTimelockState = {
			isActive: !!queryResult?.is_active,
			timeEnforcementEnds:
				queryResult?.time_enforcement_ends && queryResult?.time_enforcement_ends !== '0'
					? new Date(parseInt(queryResult.time_enforcement_ends, 10) * 1000)
					: undefined,
			enforcementType: queryResult?.enforcement_type ?? ReachoutTimelockEnforcementType.DEFAULT
		}
		ev.emit('connection.update', { reachoutTimeLock: result })
		return result
	}

	/**
	 * Fetches your account's new chat limits.
	 * @returns Returns the quota and the usage.
	 */
	const fetchNewChatMessageCap = async () => {
		return executeWMexQuery<NewChatMessageCapInfo>(
			{ input: { type: 'INDIVIDUAL_NEW_CHAT_MSG' } },
			QueryIds.MESSAGE_CAPPING_INFO,
			XWAPaths.xwa2_message_capping_info,
			query,
			generateMessageTag
		)
	}

	return {
		type: 'md' as 'md',
		ws,
		ev,
		authState: { creds, keys },
		signalRepository,
		get user() {
			return authState.creds.me
		},
		generateMessageTag,
		query,
		waitForMessage,
		waitForSocketOpen,
		sendRawMessage,
		sendNode,
		logout,
		end,
		registerSocketEndHandler,
		onUnexpectedError,
		uploadPreKeys,
		uploadPreKeysToServerIfRequired,
		digestKeyBundle,
		rotateSignedPreKey,
		// Media routing (Stage 11): per-socket `media_conn`-derived host so
		// any layer above can route its downloads / uploads through the
		// shard WhatsApp assigned this connection.
		refreshMediaConn,
		getMediaHost,
		requestPairingCode,
		updateServerTimeOffset,
		sendUnifiedSession,
		wamBuffer: publicWAMBuffer,
		/** Waits for the connection to WA to reach a state */
		waitForConnectionUpdate: bindWaitForConnectionUpdate(ev),
		sendWAMBuffer,
		executeUSyncQuery,
		onWhatsApp,
		fetchAccountReachoutTimelock,
		fetchNewChatMessageCap
	}
}

/**
 * map the websocket error to the right type
 * so it can be retried by the caller
 * */
function mapWebSocketError(handler: (err: Error) => void) {
	return (error: Error) => {
		handler(new Boom(`WebSocket Error (${error?.message})`, { statusCode: getCodeFromWSError(error), data: error }))
	}
}
