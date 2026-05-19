import type { proto } from '../../WAProto/index.js'
import type { ILogger } from './logger'
import { LRUCache } from 'lru-cache'
import NodeCache from '@cacheable/node-cache'

const MESSAGE_KEY_SEPARATOR = '\u0000'

/** Timeout for session recreation - 1 hour */
const RECREATE_SESSION_TIMEOUT = 60 * 60 // 1 hour in seconds
const PHONE_REQUEST_DELAY = 3000
/** Default threshold for consecutive failures before forcing session recreation */
const DEFAULT_CONSECUTIVE_FAILURE_THRESHOLD = 3
/** TTL for consecutive failure tracking - 30 minutes */
const CONSECUTIVE_FAILURE_TTL = 30 * 60
export interface RecentMessageKey {
	to: string
	id: string
}

export interface RecentMessage {
	message: proto.IMessage
	timestamp: number
}

export interface SessionRecreateHistory {
	[jid: string]: number // timestamp
}

export interface RetryCounter {
	[messageId: string]: number
}

export type PendingPhoneRequest = Record<string, ReturnType<typeof setTimeout>>

export interface RetryStatistics {
	totalRetries: number
	successfulRetries: number
	failedRetries: number
	mediaRetries: number
	sessionRecreations: number
	phoneRequests: number
	consecutiveFailureRecreations: number
}

export interface ConsecutiveFailureInfo {
	count: number
	lastMessageId: string
	firstFailureTime: number
}

// Retry reason codes matching WhatsApp Web's Signal error codes.
export enum RetryReason {
	UnknownError = 0,
	SignalErrorNoSession = 1,
	SignalErrorInvalidKey = 2,
	SignalErrorInvalidKeyId = 3,
	/** MAC verification failed - most common cause of decryption failures */
	SignalErrorInvalidMessage = 4,
	SignalErrorInvalidSignature = 5,
	SignalErrorFutureMessage = 6,
	/** Explicit MAC failure - session is definitely out of sync */
	SignalErrorBadMac = 7,
	SignalErrorInvalidSession = 8,
	SignalErrorInvalidMsgKey = 9,
	BadBroadcastEphemeralSetting = 10,
	UnknownCompanionNoPrekey = 11,
	AdvFailure = 12,
	StatusRevokeDelay = 13
}

/** Error codes that indicate a MAC failure and require immediate session recreation */
const MAC_ERROR_CODES = new Set([RetryReason.SignalErrorInvalidMessage, RetryReason.SignalErrorBadMac])

/** All explicitly-named RetryReason values; used to validate inbound error codes. */
const KNOWN_RETRY_REASONS: ReadonlySet<number> = new Set(
	Object.values(RetryReason).filter((v): v is number => typeof v === 'number')
)

export class MessageRetryManager {
	private recentMessagesMap = new NodeCache<RecentMessage>({
		stdTTL: 5 * 60, // 5 minutes in seconds
		useClones: false
	})
	private messageKeyIndex = new Map<string, string>()
	private sessionRecreateHistory = new NodeCache<number>({
		stdTTL: RECREATE_SESSION_TIMEOUT * 2,
		useClones: false
	})
	private retryCounters = new NodeCache<number>({
		stdTTL: 15 * 60,
		useClones: false
	}) // 15 minutes TTL
	// LRUCache (not NodeCache) on purpose: under burst, LRUCache evicts the
	// least-recently-used entry to make room; NodeCache.maxKeys would REFUSE
	// new inserts past the cap, silently breaking the base-key collision
	// check that upstream #2506 relies on for session reset.
	private baseKeys = new LRUCache<string, Uint8Array>({
		max: 1024,
		ttl: 15 * 60 * 1000,
		ttlAutopurge: true
	})
	private consecutiveFailures = new NodeCache<ConsecutiveFailureInfo>({
		stdTTL: CONSECUTIVE_FAILURE_TTL,
		useClones: false
	})
	private pendingPhoneRequests: PendingPhoneRequest = {}
	private readonly maxMsgRetryCount: number = 5
	private readonly consecutiveFailureThreshold: number = DEFAULT_CONSECUTIVE_FAILURE_THRESHOLD
	private statistics: RetryStatistics = {
		totalRetries: 0,
		successfulRetries: 0,
		failedRetries: 0,
		mediaRetries: 0,
		sessionRecreations: 0,
		phoneRequests: 0,
		consecutiveFailureRecreations: 0
	}

	constructor(
		private logger: ILogger,
		maxMsgRetryCount: number
	) {
		this.maxMsgRetryCount = maxMsgRetryCount
	}

	/**
	 * Add a recent message to the cache for retry handling
	 */
	addRecentMessage(to: string, id: string, message: proto.IMessage): void {
		const key: RecentMessageKey = { to, id }
		const keyStr = this.keyToString(key)

		// Add new message
		this.recentMessagesMap.set(keyStr, {
			message,
			timestamp: Date.now()
		})
		this.messageKeyIndex.set(id, keyStr)

		this.logger.debug(`Added message to retry cache: ${to}/${id}`)
	}

	/**
	 * Get a recent message from the cache
	 */
	getRecentMessage(to: string, id: string): RecentMessage | undefined {
		const key: RecentMessageKey = { to, id }
		const keyStr = this.keyToString(key)
		return this.recentMessagesMap.get(keyStr)
	}

	/**
	 * Check if a session should be recreated based on retry count, history, and error code.
	 * MAC errors (codes 4 and 7) trigger immediate session recreation regardless of timeout.
	 */
	shouldRecreateSession(
		jid: string,
		hasSession: boolean,
		errorCode?: RetryReason
	): { reason: string; recreate: boolean } {
		const consecutiveCount = this.getConsecutiveFailureCount(jid)
		const prevTime = this.sessionRecreateHistory.get(jid)
		const timeSinceLastRecreation = prevTime ? Date.now() - prevTime : undefined

		this.logger.debug(
			{
				jid,
				hasSession,
				errorCode: errorCode !== undefined ? RetryReason[errorCode] : undefined,
				consecutiveFailures: consecutiveCount,
				lastRecreation: prevTime ? new Date(prevTime).toISOString() : 'never',
				timeSinceLastRecreationMs: timeSinceLastRecreation
			},
			'evaluating session recreation'
		)

		// If we don't have a session, always recreate
		if (!hasSession) {
			this.sessionRecreateHistory.set(jid, Date.now())
			this.statistics.sessionRecreations++
			this.logger.info({ jid }, 'recreating session: no existing session')
			return {
				reason: "we don't have a session with them",
				recreate: true
			}
		}

		// IMMEDIATE recreation for MAC errors - session is definitely out of sync
		if (errorCode !== undefined && MAC_ERROR_CODES.has(errorCode)) {
			this.sessionRecreateHistory.set(jid, Date.now())
			this.statistics.sessionRecreations++
			this.logger.warn(
				{ jid, errorCode: RetryReason[errorCode] },
				'MAC error detected, forcing immediate session recreation'
			)
			return {
				reason: `MAC error (code ${errorCode}: ${RetryReason[errorCode]}), immediate session recreation`,
				recreate: true
			}
		}

		const now = Date.now()

		// If no previous recreation or it's been more than an hour
		if (!prevTime || now - prevTime > RECREATE_SESSION_TIMEOUT * 1000) {
			this.sessionRecreateHistory.set(jid, now)
			this.statistics.sessionRecreations++
			this.logger.info(
				{ jid, timeSinceLastMs: prevTime ? now - prevTime : 'never' },
				'recreating session: timeout exceeded since last recreation'
			)
			return {
				reason: 'retry count > 1 and over an hour since last recreation',
				recreate: true
			}
		}

		this.logger.debug(
			{ jid, timeSinceLastRecreationMs: timeSinceLastRecreation, timeoutMs: RECREATE_SESSION_TIMEOUT * 1000 },
			'not recreating session: within timeout window'
		)
		return { reason: '', recreate: false }
	}

	/**
	 * Parse error code from retry receipt's retry node.
	 * Returns undefined if no error code is present, RetryReason.UnknownError
	 * if the code is present but doesn't match a named enum value (e.g. a
	 * new code WhatsApp added that we haven't mapped yet).
	 */
	parseRetryErrorCode(errorAttr: string | undefined): RetryReason | undefined {
		if (errorAttr === undefined || errorAttr === '') {
			return undefined
		}

		const code = parseInt(errorAttr, 10)
		if (Number.isNaN(code)) {
			return undefined
		}

		// Explicit set-membership check rather than a numeric range:
		// the enum is not guaranteed to stay contiguous as WhatsApp adds codes.
		if (KNOWN_RETRY_REASONS.has(code)) {
			return code as RetryReason
		}

		return RetryReason.UnknownError
	}

	/**
	 * Check if an error code indicates a MAC failure
	 */
	isMacError(errorCode: RetryReason | undefined): boolean {
		return errorCode !== undefined && MAC_ERROR_CODES.has(errorCode)
	}

	/**
	 * Record a retry failure for a JID and check if consecutive failure threshold is reached.
	 * Option C: Track consecutive failures per participant to detect persistent session issues.
	 * @returns true if threshold reached and session should be recreated
	 */
	recordRetryFailure(jid: string, messageId: string): {
		shouldRecreate: boolean
		consecutiveCount: number
		reason: string
	} {
		const existing = this.consecutiveFailures.get(jid)
		const now = Date.now()

		if (existing) {
			existing.count++
			existing.lastMessageId = messageId
			this.consecutiveFailures.set(jid, existing)

			if (existing.count >= this.consecutiveFailureThreshold) {
				this.logger.warn(
					{
						jid,
						consecutiveCount: existing.count,
						threshold: this.consecutiveFailureThreshold,
						firstFailure: new Date(existing.firstFailureTime).toISOString(),
						messageId
					},
					'consecutive failure threshold reached, forcing session recreation'
				)
				// Reset after triggering recreation
				this.consecutiveFailures.del(jid)
				this.statistics.consecutiveFailureRecreations++
				return {
					shouldRecreate: true,
					consecutiveCount: existing.count,
					reason: `${existing.count} consecutive failures (threshold: ${this.consecutiveFailureThreshold})`
				}
			}

			this.logger.debug(
				{ jid, consecutiveCount: existing.count, threshold: this.consecutiveFailureThreshold, messageId },
				'recorded consecutive retry failure'
			)
			return { shouldRecreate: false, consecutiveCount: existing.count, reason: '' }
		}

		// First failure for this JID
		this.consecutiveFailures.set(jid, {
			count: 1,
			lastMessageId: messageId,
			firstFailureTime: now
		})
		this.logger.debug({ jid, messageId }, 'recorded first retry failure for participant')
		return { shouldRecreate: false, consecutiveCount: 1, reason: '' }
	}

	/**
	 * Clear consecutive failure tracking for a JID (call on success)
	 */
	clearConsecutiveFailures(jid: string): void {
		if (this.consecutiveFailures.has(jid)) {
			this.logger.debug({ jid }, 'clearing consecutive failure counter on success')
			this.consecutiveFailures.del(jid)
		}
	}

	/**
	 * Get current consecutive failure count for a JID
	 */
	getConsecutiveFailureCount(jid: string): number {
		return this.consecutiveFailures.get(jid)?.count || 0
	}

	/**
	 * Increment retry counter for a message
	 */
	incrementRetryCount(messageId: string): number {
		this.retryCounters.set(messageId, (this.retryCounters.get(messageId) || 0) + 1)
		this.statistics.totalRetries++
		return this.retryCounters.get(messageId)!
	}

	/**
	 * Get retry count for a message
	 */
	getRetryCount(messageId: string): number {
		return this.retryCounters.get(messageId) || 0
	}

	/**
	 * Check if message has exceeded maximum retry attempts
	 */
	hasExceededMaxRetries(messageId: string): boolean {
		return this.getRetryCount(messageId) >= this.maxMsgRetryCount
	}

	/**
	 * Mark retry as successful
	 */
	markRetrySuccess(messageId: string): void {
		this.statistics.successfulRetries++
		// Clean up retry counter for successful message
		this.retryCounters.del(messageId)
		this.cancelPendingPhoneRequest(messageId)
		this.removeRecentMessage(messageId)
	}

	/**
	 * Mark retry as failed
	 */
	markRetryFailed(messageId: string): void {
		this.statistics.failedRetries++
		this.retryCounters.del(messageId)
		this.cancelPendingPhoneRequest(messageId)
		this.removeRecentMessage(messageId)
	}

	/**
	 * Schedule a phone request with delay
	 */
	schedulePhoneRequest(messageId: string, callback: () => void, delay: number = PHONE_REQUEST_DELAY): void {
		// Cancel any existing request for this message
		this.cancelPendingPhoneRequest(messageId)

		this.pendingPhoneRequests[messageId] = setTimeout(() => {
			delete this.pendingPhoneRequests[messageId]
			this.statistics.phoneRequests++
			callback()
		}, delay)

		this.logger.debug(`Scheduled phone request for message ${messageId} with ${delay}ms delay`)
	}

	/**
	 * Cancel pending phone request
	 */
	cancelPendingPhoneRequest(messageId: string): void {
		const timeout = this.pendingPhoneRequests[messageId]
		if (timeout) {
			clearTimeout(timeout)
			delete this.pendingPhoneRequests[messageId]
			this.logger.debug(`Cancelled pending phone request for message ${messageId}`)
		}
	}

	/**
	 * Called from `registerSocketEndHandler` when the socket dies.
	 * Uses NodeCache.close() to release internal setInterval timers
	 * (one per NodeCache). LRUCache and Map use .clear() since they
	 * carry no timers.
	 */
	clear(): void {
		this.recentMessagesMap.close()
		this.messageKeyIndex.clear()
		this.sessionRecreateHistory.close()
		this.retryCounters.close()
		this.baseKeys.clear()
		this.consecutiveFailures.close()
		for (const messageId of Object.keys(this.pendingPhoneRequests)) {
			this.cancelPendingPhoneRequest(messageId)
		}

		this.statistics = {
			totalRetries: 0,
			successfulRetries: 0,
			failedRetries: 0,
			mediaRetries: 0,
			sessionRecreations: 0,
			phoneRequests: 0,
			consecutiveFailureRecreations: 0
		}
	}

	saveBaseKey(addr: string, msgId: string, baseKey: Uint8Array): void {
		this.baseKeys.set(`${addr}:${msgId}`, baseKey)
	}

	hasSameBaseKey(addr: string, msgId: string, baseKey: Uint8Array): boolean {
		const stored = this.baseKeys.get(`${addr}:${msgId}`)
		if (!stored || stored.length !== baseKey.length) {
			return false
		}

		for (let i = 0; i < stored.length; i++) {
			if (stored[i] !== baseKey[i]) return false
		}

		return true
	}

	deleteBaseKey(addr: string, msgId: string): void {
		this.baseKeys.delete(`${addr}:${msgId}`)
	}

	private keyToString(key: RecentMessageKey): string {
		return `${key.to}${MESSAGE_KEY_SEPARATOR}${key.id}`
	}

	private removeRecentMessage(messageId: string): void {
		const keyStr = this.messageKeyIndex.get(messageId)
		if (!keyStr) {
			return
		}

		this.recentMessagesMap.del(keyStr)
		this.messageKeyIndex.delete(messageId)
	}

	/**
	 * Get retry statistics for monitoring/metrics
	 */
	getStatistics(): RetryStatistics {
		return { ...this.statistics }
	}

	/**
	 * Get current cache sizes for debugging
	 */
	getCacheSizes(): {
		recentMessages: number
		retryCounters: number
		sessionRecreateHistory: number
		consecutiveFailures: number
		pendingPhoneRequests: number
	} {
		return {
			recentMessages: this.recentMessagesMap.keys().length,
			retryCounters: this.retryCounters.keys().length,
			sessionRecreateHistory: this.sessionRecreateHistory.keys().length,
			consecutiveFailures: this.consecutiveFailures.keys().length,
			pendingPhoneRequests: Object.keys(this.pendingPhoneRequests).length
		}
	}
}
