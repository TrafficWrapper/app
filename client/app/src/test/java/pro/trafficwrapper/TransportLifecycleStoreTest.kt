package pro.trafficwrapper

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
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
    fun autoDownloadPreferencesDefaultOffAndWifiOnlyWhenEnabled() {
        assertFalse(autoDownloadUpdatesPreference(null))
        assertFalse(autoDownloadUpdatesPreference(false))
        assertTrue(autoDownloadUpdatesPreference(true))

        assertTrue(autoDownloadWifiPreference(null))
        assertFalse(autoDownloadWifiPreference(false))
        assertTrue(autoDownloadWifiPreference(true))

        assertFalse(autoDownloadMobilePreference(null))
        assertFalse(autoDownloadMobilePreference(false))
        assertTrue(autoDownloadMobilePreference(true))
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

    @Test
    fun vpnPreferenceDefaultsOff() {
        assertFalse(vpnPreference(null))
        assertFalse(vpnPreference(false))
        assertTrue(vpnPreference(true))
    }

    @Test
    fun vpnModeDefaultsFullAndPersistsSplit() {
        val context = FakeContext()

        assertEquals(VpnTrafficMode.FULL, TransportLifecycleStore.vpnMode(context))

        TransportLifecycleStore.setVpnMode(context, VpnTrafficMode.SPLIT)
        assertEquals(VpnTrafficMode.SPLIT, TransportLifecycleStore.vpnMode(context))
    }

    @Test
    fun vpnKillSwitchDefaultsOnAndPersists() {
        val context = FakeContext()

        assertTrue(vpnKillSwitchPreference(null))
        assertTrue(TransportLifecycleStore.vpnKillSwitchEnabled(context))

        TransportLifecycleStore.setVpnKillSwitchEnabled(context, false)
        assertFalse(TransportLifecycleStore.vpnKillSwitchEnabled(context))

        TransportLifecycleStore.setVpnKillSwitchEnabled(context, true)
        assertTrue(TransportLifecycleStore.vpnKillSwitchEnabled(context))
    }

    @Test
    fun vpnAllowedAppsDefaultsTelegramAndPersistsSanitizedSet() {
        val context = FakeContext()

        assertEquals(setOf(TELEGRAM_PACKAGE), TransportLifecycleStore.vpnAllowedApps(context))

        TransportLifecycleStore.setVpnAllowedApps(context, setOf(" org.telegram.messenger ", "", "com.example.app"))
        assertEquals(
            setOf("com.example.app", TELEGRAM_PACKAGE),
            TransportLifecycleStore.vpnAllowedApps(context),
        )
    }

    @Test
    fun vpnAllowedAppsPreferenceKeepsExplicitEmptySet() {
        assertEquals(emptySet<String>(), vpnAllowedAppsPreference(emptySet()))
    }

    @Test
    fun lastVpnUdpRoutePersistsTrimmedValue() {
        val context = FakeContext()

        assertEquals("", TransportLifecycleStore.lastVpnUdpRoute(context))

        TransportLifecycleStore.setLastVpnUdpRoute(context, " netstack:default ")
        assertEquals("netstack:default", TransportLifecycleStore.lastVpnUdpRoute(context))
    }
}

private class FakeContext : ContextWrapper(null) {
    private val prefs = FakeSharedPreferences()

    override fun getApplicationContext(): Context = this

    override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = prefs
}

private class FakeSharedPreferences : SharedPreferences {
    private val values = linkedMapOf<String, Any?>()

    override fun getAll(): MutableMap<String, *> = LinkedHashMap(values)

    override fun getString(key: String?, defValue: String?): String? =
        values[key] as? String ?: defValue

    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
        @Suppress("UNCHECKED_CAST")
        (values[key] as? Set<String>)?.toMutableSet() ?: defValues

    override fun getInt(key: String?, defValue: Int): Int =
        values[key] as? Int ?: defValue

    override fun getLong(key: String?, defValue: Long): Long =
        values[key] as? Long ?: defValue

    override fun getFloat(key: String?, defValue: Float): Float =
        values[key] as? Float ?: defValue

    override fun getBoolean(key: String?, defValue: Boolean): Boolean =
        values[key] as? Boolean ?: defValue

    override fun contains(key: String?): Boolean =
        values.containsKey(key)

    override fun edit(): SharedPreferences.Editor = Editor()

    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit

    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit

    private inner class Editor : SharedPreferences.Editor {
        private val pending = linkedMapOf<String, Any?>()
        private val removals = mutableSetOf<String>()
        private var clearRequested = false

        override fun putString(key: String?, value: String?): SharedPreferences.Editor = put(key, value)

        override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor =
            put(key, values?.toSet())

        override fun putInt(key: String?, value: Int): SharedPreferences.Editor = put(key, value)

        override fun putLong(key: String?, value: Long): SharedPreferences.Editor = put(key, value)

        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = put(key, value)

        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = put(key, value)

        override fun remove(key: String?): SharedPreferences.Editor {
            key?.let { removals += it }
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            clearRequested = true
            return this
        }

        override fun commit(): Boolean {
            if (clearRequested) values.clear()
            removals.forEach { values.remove(it) }
            values.putAll(pending)
            return true
        }

        override fun apply() {
            commit()
        }

        private fun put(key: String?, value: Any?): SharedPreferences.Editor {
            key?.let { pending[it] = value }
            return this
        }
    }
}
