/**
 * Decide whether to keep a pairing socket alive after its QR refs are
 * exhausted.
 *
 * The QR refs (scan flow) run out after the QR-refresh cycle (~2:40). But in
 * the "link with phone number" (pair-code) flow the user types a code instead
 * of scanning, and WhatsApp keeps that code valid server-side beyond the
 * QR-ref cycle. So when a pairing code is active, keep the socket alive up to
 * the code's max lifetime rather than tearing it down on ref exhaustion.
 *
 * Returns the remaining time (ms) to keep the socket alive, or null if it
 * should end now (no pairing code active, or the max lifetime has elapsed).
 */
export function pairCodeKeepAliveMs(
	hasPairingCode: boolean,
	startedAtMs: number,
	nowMs: number,
	maxLifetimeMs: number,
): number | null {
	if (!hasPairingCode) {
		return null
	}

	const remaining = maxLifetimeMs - (nowMs - startedAtMs)
	return remaining > 0 ? remaining : null
}
