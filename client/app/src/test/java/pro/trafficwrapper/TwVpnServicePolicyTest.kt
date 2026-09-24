package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Test

class TwVpnServicePolicyTest {
    @Test
    fun alwaysOnSystemStartIsTreatedAsVpnStart() {
        assertEquals(VpnStartKind.SYSTEM_START, vpnStartKind("android.net.VpnService"))
        assertEquals(VpnStartKind.SYSTEM_START, vpnStartKind(null))
    }

    @Test
    fun appActionsKeepTheirMeaning() {
        assertEquals(VpnStartKind.APP_START, vpnStartKind(TwVpnService.ACTION_VPN_START))
        assertEquals(VpnStartKind.STOP, vpnStartKind(TwVpnService.ACTION_VPN_STOP))
        assertEquals(VpnStartKind.IGNORE, vpnStartKind("pro.trafficwrapper.action.SOMETHING_ELSE"))
    }
}
