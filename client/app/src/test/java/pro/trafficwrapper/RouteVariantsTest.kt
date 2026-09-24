package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class RouteVariantsTest {
    private fun cursor(vararg keys: String, remembered: String? = null): VariantCursor<String> =
        VariantCursor(keys.toList(), { it }, remembered)

    @Test
    fun singleVariantNeverMoves() {
        val cursor = cursor("only")
        repeat(10) { assertFalse(cursor.onProbe(healthy = false, nowMs = it * 60_000L)) }
        assertEquals("only", cursor.current)
        assertFalse(cursor.advance())
    }

    @Test
    fun advancesAfterTwoConsecutiveFailures() {
        val cursor = cursor("a", "b", "c")
        assertFalse(cursor.onProbe(false, 0))
        assertTrue(cursor.onProbe(false, 1_000))
        assertEquals("b", cursor.current)
        // A success in between resets the failure streak.
        assertFalse(cursor.onProbe(false, 2_000))
        assertFalse(cursor.onProbe(true, 3_000))
        assertFalse(cursor.onProbe(false, 4_000))
        assertEquals("b", cursor.current)
        assertTrue(cursor.onProbe(false, 5_000))
        assertEquals("c", cursor.current)
    }

    @Test
    fun advancesAfterThirtySecondsWithoutReady() {
        val cursor = VariantCursor(listOf("a", "b"), { it }, failuresBeforeAdvance = 5)
        assertFalse(cursor.onProbe(false, 1_000))
        assertFalse(cursor.onProbe(false, 30_999))
        assertTrue(cursor.onProbe(false, 31_000))
        assertEquals("b", cursor.current)
    }

    @Test
    fun wrapsAroundToFirstVariant() {
        val cursor = cursor("v4", "v6")
        assertTrue(cursor.advance())
        assertEquals("v6", cursor.current)
        assertTrue(cursor.advance())
        assertEquals("v4", cursor.current)
        cursor.onProbe(false, 0)
        cursor.onProbe(false, 1)
        assertEquals("v6", cursor.current)
        cursor.onProbe(false, 2)
        cursor.onProbe(false, 3)
        assertEquals("v4", cursor.current)
    }

    @Test
    fun startsFromRememberedKeyAndIgnoresUnknownOne() {
        assertEquals("b", cursor("a", "b", "c", remembered = "b").current)
        assertEquals("a", cursor("a", "b", remembered = "gone").current)
        assertEquals("a", cursor("a", "b", remembered = null).current)
        assertNull(VariantCursor(emptyList<String>(), { it }).current)
    }

    @Test
    fun variantSlotKeepsCursorWhileKeysAreUnchanged() {
        val slot = VariantSlot<String> { it }
        val first = slot.sync(listOf("a", "b"), rememberedKey = null)!!
        first.advance()
        assertTrue(slot.sync(listOf("a", "b"), rememberedKey = "a") === first)
        assertEquals("b", slot.cursor?.current)
        // New list (e.g. IPv6 appeared): the current key is kept when still present.
        val second = slot.sync(listOf("a", "b", "c"), rememberedKey = "a")!!
        assertEquals("b", second.current)
        // Network change: restart from the remembered key.
        assertEquals("c", slot.reset(listOf("a", "b", "c"), rememberedKey = "c")?.current)
        assertNull(slot.sync(emptyList(), rememberedKey = "a"))
    }

    @Test
    fun variantKeyAndTelemetryLabel() {
        val key = routeVariantKey("w1", "xhttp", "XHTTP", IpFamily.V6, "")
        assertEquals("w1|xhttp|xhttp|v6|", key)
        assertEquals("xhttp/xhttp/v6/none", routeVariantTelemetryLabel(key))
        assertEquals(
            "reality/tcp/v4/vision",
            routeVariantTelemetryLabel(routeVariantKey("w1", "reality", "tcp", IpFamily.V4, REALITY_FLOW_VISION)),
        )
        assertEquals("", routeVariantTelemetryLabel(""))
    }

    @Test
    fun orderForNetworkPrefersIpv4AndDropsIpv6WithoutIt() {
        val variants = listOf("a4" to IpFamily.V4, "b4" to IpFamily.V4, "a6" to IpFamily.V6)
        fun order(families: NetworkIpFamilies) =
            RouteVariants.orderForNetwork(variants, { it.second }, families).map { it.first }
        assertEquals(listOf("a4", "b4"), order(NetworkIpFamilies.DEFAULT))
        assertEquals(listOf("a4", "b4", "a6"), order(NetworkIpFamilies.ALL))
        assertEquals(listOf("a6", "a4", "b4"), order(NetworkIpFamilies(ipv4 = false, ipv6 = true)))
        assertEquals(listOf("a4", "b4"), order(NetworkIpFamilies(ipv4 = false, ipv6 = false)))
    }

    @Test
    fun networkIpFamiliesNeedGlobalAddressAndDefaultRoute() {
        val v4 = InetAddress.getByName("192.0.2.10")
        val global6 = InetAddress.getByName("2001:db8::10")
        val linkLocal6 = InetAddress.getByName("fe80::1")
        val ula6 = InetAddress.getByName("fd00::1")
        assertEquals(
            NetworkIpFamilies(ipv4 = true, ipv6 = true),
            networkIpFamiliesOf(listOf(v4, global6), setOf(IpFamily.V4, IpFamily.V6)),
        )
        assertEquals(
            NetworkIpFamilies(ipv4 = true, ipv6 = false),
            networkIpFamiliesOf(listOf(v4, linkLocal6, ula6), setOf(IpFamily.V4, IpFamily.V6)),
        )
        assertEquals(
            NetworkIpFamilies(ipv4 = true, ipv6 = false),
            networkIpFamiliesOf(listOf(v4, global6), setOf(IpFamily.V4)),
        )
        assertTrue(networkIpFamiliesOf(listOf(global6), setOf(IpFamily.V6)).v6Only)
    }

    @Test
    fun bareIpv6AddressStripsBrackets() {
        assertEquals("2001:db8::1", bareIpv6Address("[2001:db8::1]"))
        assertEquals("2001:db8::1", bareIpv6Address(" 2001:db8::1 "))
        assertEquals("", bareIpv6Address(""))
    }
}
