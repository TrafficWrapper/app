package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BatteryRestrictionTest {
    @Test
    fun huaweiExemptKeepsOemGuideButDoesNotTriggerMainRestriction() {
        val state = batteryRestrictionStateFromSignals(
            batteryRestricted = false,
            backgroundRestricted = false,
            manufacturer = "HUAWEI",
            brand = "HBN-LX9",
            oemHintAcknowledged = false,
        )

        assertFalse(state.restricted)
        assertFalse(state.batteryOptimizationRestricted)
        assertFalse(state.backgroundRestricted)
        assertTrue(state.oemHintNeeded)
        assertEquals(OEM_MAKER_HUAWEI, state.oemMakerKey)
        assertTrue(oemBatteryGuideFor(state.oemMakerKey).body.contains("Запуск приложений"))
        assertTrue(oemDisplayName(state.oemMakerKey).contains("Huawei"))
    }

    @Test
    fun huaweiAckSuppressesOemOnlyHint() {
        val state = batteryRestrictionStateFromSignals(
            batteryRestricted = false,
            backgroundRestricted = false,
            manufacturer = "HONOR",
            brand = "HBN-LX9",
            oemHintAcknowledged = true,
        )

        assertFalse(state.restricted)
        assertFalse(state.oemHintNeeded)
        assertEquals(OEM_MAKER_HUAWEI, state.oemMakerKey)
    }

    @Test
    fun samsungExemptDoesNotNeedOemHint() {
        val state = batteryRestrictionStateFromSignals(
            batteryRestricted = false,
            backgroundRestricted = false,
            manufacturer = "samsung",
            brand = "samsung",
            oemHintAcknowledged = false,
        )

        assertFalse(state.restricted)
        assertFalse(state.oemHintNeeded)
        assertEquals(OEM_MAKER_SAMSUNG, state.oemMakerKey)
    }

    @Test
    fun androidBatteryRestrictionOverridesOemAck() {
        val state = batteryRestrictionStateFromSignals(
            batteryRestricted = true,
            backgroundRestricted = false,
            manufacturer = "samsung",
            brand = "samsung",
            oemHintAcknowledged = true,
        )

        assertTrue(state.restricted)
        assertTrue(state.batteryOptimizationRestricted)
        assertFalse(state.oemHintNeeded)
    }

    @Test
    fun backgroundRestrictedDoesNotTriggerMainBatteryBannerWhenExempt() {
        val state = batteryRestrictionStateFromSignals(
            batteryRestricted = false,
            backgroundRestricted = true,
            manufacturer = "HUAWEI",
            brand = "HBN-LX9",
            oemHintAcknowledged = false,
        )

        assertFalse(state.restricted)
        assertFalse(state.batteryOptimizationRestricted)
        assertTrue(state.backgroundRestricted)
        assertTrue(state.oemHintNeeded)
    }
}
