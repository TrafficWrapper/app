package pro.trafficwrapper

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportLifecycleStoreTest {
    @Test
    fun httpProxyPreferenceDefaultsFalse() {
        assertFalse(httpProxyPreference(null))
        assertFalse(httpProxyPreference(false))
        assertTrue(httpProxyPreference(true))
    }

    @Test
    fun directUpdateFallbackPreferenceDefaultsFalse() {
        assertFalse(directUpdateFallbackPreference(null))
        assertFalse(directUpdateFallbackPreference(false))
        assertTrue(directUpdateFallbackPreference(true))
    }

    @Test
    fun discoverySubscriptionPreferenceDefaultsFalse() {
        assertFalse(discoverySubscriptionPreference(null))
        assertFalse(discoverySubscriptionPreference(false))
        assertTrue(discoverySubscriptionPreference(true))
    }

    @Test
    fun serviceNotificationsPreferenceDefaultsTrueAndThrottleIsPerTimestamp() {
        assertTrue(serviceNotificationsPreference(null))
        assertFalse(serviceNotificationsPreference(false))
        assertTrue(serviceNotificationsPreference(true))

        val minIntervalMs = 6L * 60L * 60L * 1000L
        assertTrue(shouldShowServiceNotificationAt(lastShownAtMs = 0L, nowMs = 1_000L, minIntervalMs = minIntervalMs))
        assertFalse(
            shouldShowServiceNotificationAt(
                lastShownAtMs = 1_000L,
                nowMs = 1_000L + minIntervalMs - 1L,
                minIntervalMs = minIntervalMs,
            ),
        )
        assertTrue(
            shouldShowServiceNotificationAt(
                lastShownAtMs = 1_000L,
                nowMs = 1_000L + minIntervalMs,
                minIntervalMs = minIntervalMs,
            ),
        )
    }
}
