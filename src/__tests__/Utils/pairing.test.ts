import { pairCodeKeepAliveMs } from '../../Utils/pairing'

describe('pairCodeKeepAliveMs', () => {
	const TTL = 5 * 60 * 1000 // 5 min

	it('returns null with no pairing code (QR-scan flow ends on ref exhaustion)', () => {
		expect(pairCodeKeepAliveMs(false, 0, 1000, TTL)).toBeNull()
	})

	it('returns remaining ms when a pairing code is active and within the lifetime', () => {
		expect(pairCodeKeepAliveMs(true, 0, 1000, TTL)).toBe(TTL - 1000)
		expect(pairCodeKeepAliveMs(true, 1000, 1500, 5000)).toBe(4500)
	})

	it('returns null when the lifetime is exactly reached or exceeded', () => {
		expect(pairCodeKeepAliveMs(true, 0, TTL, TTL)).toBeNull()
		expect(pairCodeKeepAliveMs(true, 0, TTL + 1, TTL)).toBeNull()
	})
})
