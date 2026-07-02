package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReauthStateTest {
    @Test
    fun detectsDeviceNotApprovedError() {
        assertTrue(isDeviceNotApprovedMessage("device is not approved"))
        assertTrue(isDeviceNotApprovedMessage("HTTP 403: Device is not approved"))
        assertFalse(isDeviceNotApprovedMessage("temporary network error"))
        assertFalse(isDeviceNotApprovedMessage(null))
    }

    @Test
    fun notApprovedStateClearsAuthorization() {
        val updated = reauthRequiredAuthState(
            AuthUiState(
                authorized = true,
                inProgress = true,
                statusTextRes = R.string.enrollment_status_approved,
                errorTextRes = R.string.enrollment_error_network,
                message = "old",
            ),
        )

        assertFalse(updated.authorized)
        assertFalse(updated.inProgress)
        assertEquals(R.string.enrollment_status_pending, updated.statusTextRes)
        assertEquals(null, updated.errorTextRes)
        assertEquals("", updated.message)
    }
}
