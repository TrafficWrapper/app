package pro.trafficwrapper

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MainActivityUiPolicyTest {
    @Test
    fun statusRoutePrefersCarryingThenActiveThenDefault() {
        assertEquals(
            "REALITY2",
            statusRouteForUi(
                TransportUiState(activeTransport = "AWG", carryingTransport = "REALITY2"),
                TransportChoice.AWG,
            ),
        )
        assertEquals(
            "AWG",
            statusRouteForUi(TransportUiState(activeTransport = "AWG"), TransportChoice.REALITY),
        )
        assertEquals(
            "REALITY",
            statusRouteForUi(TransportUiState(), TransportChoice.REALITY),
        )
        assertEquals("", statusRouteForUi(TransportUiState(), TransportChoice.AUTO))
    }

    @Test
    fun routeRegionUsesCarryingRouteAndOmitsBlankRegion() {
        val regions = mapOf("AWG" to "Operator West", "REALITY2" to "Operator East")
        val route = statusRouteForUi(
            TransportUiState(activeTransport = "AWG", carryingTransport = "REALITY2"),
            TransportChoice.AWG,
        )

        assertEquals("REALITY2", route)
        assertEquals("Operator East", routeRegionForUi(route, regions))
        assertEquals("", routeRegionForUi("REALITY", regions))
    }

    @Test
    fun statusDetailsAddRegionOnlyWhenPresent() {
        assertEquals(
            "REALITY B · Operator East · stable",
            connectedStatusDetail("REALITY B", "Operator East", "stable"),
        )
        assertEquals(
            "REALITY B · stable",
            connectedStatusDetail("REALITY B", "", "stable"),
        )
        assertEquals(
            "Connecting to REALITY B (Operator East)…",
            connectingStatusDetail(
                label = "REALITY B",
                region = "Operator East",
                fallback = "Connecting…",
                formatNoRegion = { "Connecting to $it…" },
                formatWithRegion = { label, region -> "Connecting to $label ($region)…" },
            ),
        )
        assertEquals(
            "Connecting to REALITY B…",
            connectingStatusDetail(
                label = "REALITY B",
                region = "",
                fallback = "Connecting…",
                formatNoRegion = { "Connecting to $it…" },
                formatWithRegion = { label, region -> "Connecting to $label ($region)…" },
            ),
        )
        assertEquals(
            "Connecting…",
            connectingStatusDetail(
                label = "AUTO",
                region = "Operator East",
                fallback = "Connecting…",
                formatNoRegion = { "Connecting to $it…" },
                formatWithRegion = { label, region -> "Connecting to $label ($region)…" },
            ),
        )
    }

    @Test
    fun transportModeCardSubtitlePrefersActionDetailThenRegion() {
        assertEquals("нет маршрута", transportModeCardSubtitle("нет маршрута", "Operator East"))
        assertEquals("Operator East", transportModeCardSubtitle(null, " Operator East "))
        assertEquals(null, transportModeCardSubtitle(null, ""))
    }

    @Test
    fun exchangeRecencyBucketsAreStable() {
        assertEquals("exchange now", formatExchangeRecency(null))
        assertEquals("exchange now", formatExchangeRecency(2))
        assertEquals("exchange 17s ago", formatExchangeRecency(17))
        assertEquals("exchange 2m ago", formatExchangeRecency(125))
    }

    @Test
    fun trafficBytesUseBinaryUnits() {
        assertEquals("0 B", formatTrafficBytes(-1))
        assertEquals("512 B", formatTrafficBytes(512))
        assertEquals("1.5 KB", formatTrafficBytes(1536))
        assertEquals("2.0 MB", formatTrafficBytes(2L * 1024L * 1024L))
    }

    @Test
    fun quotaParserSupportsLimitsAndOptionalUsage() {
        val quota = JSONObject(
            """
            {
              "traffic_quota_bytes": 1048576,
              "used_bytes": 262144,
              "rate_limit": "5mbit",
              "expires_at": "2026-07-03T00:00:00Z"
            }
            """.trimIndent(),
        ).toQuotaUiState()

        assertTrue(quota.hasTrafficLimit)
        assertTrue(quota.hasUsage)
        assertEquals(1_048_576L, quota.limitBytes)
        assertEquals(262_144L, quota.usedBytes)
        assertEquals(786_432L, quota.remainingBytes)
        assertEquals("5mbit", quota.rateLimit)
        assertEquals("2026-07-03T00:00:00Z", quota.expiresAt)
    }

    @Test
    fun quotaParserAllowsLimitWithoutUsage() {
        val quota = JSONObject("""{"limit_bytes": 1024, "rate_limit": "1mbit"}""").toQuotaUiState()

        assertTrue(quota.hasTrafficLimit)
        assertFalse(quota.hasUsage)
        assertEquals(1024L, quota.limitBytes)
        assertEquals(null, quota.remainingBytes)
    }

    @Test
    fun primaryButtonCancelsWhileConnecting() {
        assertEquals(PrimaryTransportAction.CANCEL_CONNECTING, primaryTransportAction(connecting = true, transportRunning = false))
        assertEquals(PrimaryTransportAction.DISCONNECT, primaryTransportAction(connecting = false, transportRunning = true))
        assertEquals(PrimaryTransportAction.CONNECT, primaryTransportAction(connecting = false, transportRunning = false))
    }

    @Test
    fun startupAutoconnectPreservesCarryingSnapshot() {
        val carrying = TransportUiState(
            handshakeEstablished = true,
            tunnelStable = true,
            activeTransport = "AWG",
            carryingTransport = "AWG",
            socksListen = "127.0.0.1:18080",
        )

        assertFalse(shouldMarkConnectInProgressOnStartup(carrying))
        assertEquals(carrying, startupAutoconnectSourceState(TransportUiState(), carrying))
        assertEquals("AWG", startupAutoconnectUiState(carrying).carryingTransport)
    }

    @Test
    fun vpnAutoRestoreOnlyWhenFeatureAndPreferenceOnAndInactive() {
        assertTrue(
            shouldAttemptVpnAutoRestore(
                vpnFeatureEnabled = true,
                vpnPreferenceEnabled = true,
                vpnActive = false,
            ),
        )
        assertFalse(
            shouldAttemptVpnAutoRestore(
                vpnFeatureEnabled = false,
                vpnPreferenceEnabled = true,
                vpnActive = false,
            ),
        )
        assertFalse(
            shouldAttemptVpnAutoRestore(
                vpnFeatureEnabled = true,
                vpnPreferenceEnabled = false,
                vpnActive = false,
            ),
        )
        assertFalse(
            shouldAttemptVpnAutoRestore(
                vpnFeatureEnabled = true,
                vpnPreferenceEnabled = true,
                vpnActive = true,
            ),
        )
        assertFalse(
            shouldAttemptVpnAutoRestore(
                vpnFeatureEnabled = true,
                vpnPreferenceEnabled = true,
                vpnActive = false,
                vpnTransition = VpnTransition.STARTING,
            ),
        )
    }
}
