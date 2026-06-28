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
}
