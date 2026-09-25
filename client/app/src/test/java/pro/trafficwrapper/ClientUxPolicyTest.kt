package pro.trafficwrapper

import android.content.Intent
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ClientUxPolicyTest {
    // --- APP-M11 ---------------------------------------------------------------------------

    @Test
    fun explicitStopVoidsDeferredConnectRequests() {
        val gate = ConnectRequestGate()
        val token = gate.begin()
        assertTrue(gate.isCurrent(token))

        gate.cancel()

        assertFalse("a Cancel/Disconnect must void the deferred start", gate.isCurrent(token))
        val next = gate.begin()
        assertTrue("a new connect after the stop is valid again", gate.isCurrent(next))
    }

    // --- APP-M12 / APP-L14 / APP-L20 ---------------------------------------------------------

    @Test
    fun userEnrollmentUsesThePendingBootstrap() {
        val state = StoredPublicPlatformState(bootstrapRaw = platformA("token-1"), pendingBootstrapRaw = platformB())

        assertEquals(platformB(), publicBootstrapForEnrollment(state, silent = false))
        assertEquals(platformA("token-1"), publicBootstrapForEnrollment(state.copy(pendingBootstrapRaw = ""), silent = false))
        assertEquals(platformB(), publicBootstrapForEnrollment(StoredPublicPlatformState(pendingBootstrapRaw = platformB()), silent = true))
    }

    @Test
    fun silentReEnrollmentNeverSwitchesPlatforms() {
        val switching = StoredPublicPlatformState(bootstrapRaw = platformA("token-1"), pendingBootstrapRaw = platformB())
        val refreshed = StoredPublicPlatformState(bootstrapRaw = platformA("token-1"), pendingBootstrapRaw = platformA("token-2"))

        assertEquals(platformA("token-1"), publicBootstrapForEnrollment(switching, silent = true))
        assertEquals(platformA("token-2"), publicBootstrapForEnrollment(refreshed, silent = true))
    }

    @Test
    fun pendingBootstrapIsRecordedAndSurvivesAnOlderEnrollment() {
        val active = StoredPublicPlatformState(bootstrapRaw = platformA("token-1"))

        val pending = withPendingPublicBootstrap(active, " ${platformB()} ")
        assertEquals(platformB(), pending.pendingBootstrapRaw)
        assertEquals(platformA("token-1"), pending.bootstrapRaw)
        assertEquals("", withPendingPublicBootstrap(active, platformA("token-1")).pendingBootstrapRaw)

        // Enrollment with A finished after B was confirmed: B stays pending (APP-L14).
        assertEquals(platformB(), pendingPublicBootstrapAfterEnrollment(platformB(), platformA("token-1")))
        // Enrollment with B itself clears it.
        assertEquals("", pendingPublicBootstrapAfterEnrollment(platformB(), " ${platformB()}"))
    }

    @Test
    fun legacyPlainBootstrapCopyMigratesIntoTheSealedState() {
        val empty = StoredPublicPlatformState()
        assertEquals(platformA("token-1"), migrateLegacyPublicBootstrap(empty, platformA("token-1"))?.pendingBootstrapRaw)

        val enrolled = StoredPublicPlatformState(bootstrapRaw = platformA("token-1"), clientBundleJson = "{}")
        assertNull("same as the enrolled one: nothing to write", migrateLegacyPublicBootstrap(enrolled, platformA("token-1")))
        assertEquals(platformB(), migrateLegacyPublicBootstrap(enrolled, platformB())?.pendingBootstrapRaw)
        assertNull(migrateLegacyPublicBootstrap(enrolled, "  "))
        assertNull(
            "a newer sealed pending bootstrap wins over the legacy copy",
            migrateLegacyPublicBootstrap(enrolled.copy(pendingBootstrapRaw = platformB()), platformA("token-9")),
        )
    }

    @Test
    fun pendingBootstrapAndReauthFlagArePersistedOptionally() {
        val state = StoredPublicPlatformState(pendingBootstrapRaw = platformB(), reauthRequired = true)
        val restored = publicPlatformStateFromJson(JSONObject(publicPlatformStateToJson(state).toString()))
        assertEquals(platformB(), restored.pendingBootstrapRaw)
        assertTrue(restored.reauthRequired)

        val legacy = publicPlatformStateFromJson(JSONObject("""{"bootstrap_raw":"x","config_pubkey_pin":"pin"}"""))
        assertEquals("", legacy.pendingBootstrapRaw)
        assertFalse(legacy.reauthRequired)
    }

    @Test
    fun refreshedTokenRestartsOnlyAnIdleEnrollment() {
        val failed = publicEnrollmentFailureState(
            AuthUiState(inProgress = true),
            publicEnrollmentFailurePolicy(IllegalStateException("bootstrap token exhausted")),
        )
        assertTrue(shouldEnrollAfterBootstrapRefresh(failed))
        assertFalse(shouldEnrollAfterBootstrapRefresh(AuthUiState(authorized = true)))
        assertFalse(shouldEnrollAfterBootstrapRefresh(AuthUiState(inProgress = true)))
    }

    // --- APP-M13 -----------------------------------------------------------------------------

    @Test
    fun terminalTokenFailureOffersImportingAnotherBootstrap() {
        val terminal = publicEnrollmentFailureState(
            AuthUiState(inProgress = true),
            publicEnrollmentFailurePolicy(
                PublicEnrollmentRejectedException(code = "token_exhausted", authenticated = true, message = "used"),
            ),
        )
        assertFalse("TERMINAL: no retry with the same token", terminal.enrollmentRetryAllowed)
        assertTrue(showImportAnotherBootstrap(terminal))
        assertFalse(showImportAnotherBootstrap(AuthUiState(inProgress = true)))
        assertFalse(showImportAnotherBootstrap(AuthUiState(authorized = true)))
    }

    @Test
    fun importingAnotherBootstrapClearsTheStoredOneOnlyWithoutEnrollment() {
        val notEnrolled = StoredPublicPlatformState(bootstrapRaw = platformA("token-1"), pendingBootstrapRaw = platformB())
        val cleared = discardPendingPublicBootstrapState(notEnrolled)
        assertEquals("", cleared.pendingBootstrapRaw)
        assertEquals("", cleared.bootstrapRaw)

        val enrolled = notEnrolled.copy(clientBundleJson = "{}")
        val kept = discardPendingPublicBootstrapState(enrolled)
        assertEquals("", kept.pendingBootstrapRaw)
        assertEquals(platformA("token-1"), kept.bootstrapRaw)
    }

    // --- APP-M14 -----------------------------------------------------------------------------

    @Test
    fun configApplyKeepsTheManualRoute() {
        val all = TransportChoice.values().toSet()
        // First apply of the process: the remembered mode.
        assertEquals(
            TransportChoice.REALITY,
            publicSelectedTransportAfterApply(TransportChoice.AUTO, initialized = false, preferred = TransportChoice.REALITY, available = all),
        )
        // Later applies keep the current selection instead of forcing AUTO.
        assertEquals(
            TransportChoice.REALITY,
            publicSelectedTransportAfterApply(TransportChoice.REALITY, initialized = true, preferred = TransportChoice.AUTO, available = all),
        )
        // The route disappeared from the config: back to AUTO.
        assertEquals(
            TransportChoice.AUTO,
            publicSelectedTransportAfterApply(
                TransportChoice.REALITY,
                initialized = true,
                preferred = TransportChoice.REALITY,
                available = setOf(TransportChoice.AUTO, TransportChoice.AWG),
            ),
        )
    }

    @Test
    fun availableChoicesFollowTheConfigSlots() {
        val awg = PublicRouteConfig("awg", true, "w.example", 51820, "", "", params = JSONObject())
        val slots = PublicPlatformRouteSlots(
            awg = awg,
            reality = RealityUiConfig(address = "incomplete"),
            routePriorities = mapOf("AWG" to 0, "REALITY" to 1),
        )
        assertEquals(setOf(TransportChoice.AUTO, TransportChoice.AWG), publicAvailableTransportChoices(slots))
    }

    @Test
    fun reauthFlagIsClearedOnlyByAnApprovedEnrollment() {
        assertTrue(publicReauthRequiredAfterEnrollment(current = true, status = "pending"))
        assertFalse(publicReauthRequiredAfterEnrollment(current = true, status = "approved"))
        assertFalse(publicReauthRequiredAfterEnrollment(current = false, status = "pending"))
    }

    // --- APP-L12 / APP-L13 -------------------------------------------------------------------

    @Test
    fun expiredStoredBootstrapStillNamesTheCurrentServer() {
        val expiredCurrent = platformA("token-1", expires = "2020-01-01T00:00:00Z")
        val incoming = PublicPlatformConfigParser.parseBootstrap(platformA("token-2"))

        assertEquals("https://orch-a.dev", parseBootstrapIgnoringExpiry(expiredCurrent)?.orchestratorUrl)
        assertTrue(publicBootstrapMatchesActive(expiredCurrent, incoming))
        assertEquals(ExternalBootstrapDecision.REFRESH, externalBootstrapDecision(expiredCurrent, incoming))
    }

    @Test
    fun replaceDialogListsEveryChangedTrustedField() {
        val current = PublicPlatformConfigParser.parseBootstrap(platformA("token-1"))
        val samUrlOtherKeys = PublicPlatformConfigParser.parseBootstrap(
            platformA("token-2").replace("pin-a", "pin-evil").replace("noise-a", "noise-evil"),
        )

        val changes = externalBootstrapTrustedFieldChanges(current, samUrlOtherKeys)

        assertEquals(listOf("config_pubkey_pin", "orch_noise_public"), changes.map { it.field })
        assertTrue(changes.all { it.keyMaterial })
        assertEquals("pin-a", changes.first().current)
        assertEquals("pin-evil", changes.first().incoming)
        assertTrue(externalBootstrapNeedsSecondConfirmation(replacesExisting = true, changes = changes))
        assertFalse(externalBootstrapNeedsSecondConfirmation(replacesExisting = false, changes = changes))

        val otherServerOnly = externalBootstrapTrustedFieldChanges(
            current,
            PublicPlatformConfigParser.parseBootstrap(platformA("token-2").replace("orch-a.dev", "orch-c.dev")),
        )
        assertEquals(listOf("orchestrator_url"), otherServerOnly.map { it.field })
        assertFalse(externalBootstrapNeedsSecondConfirmation(replacesExisting = true, changes = otherServerOnly))
    }

    // --- APP-L15 / APP-L16 -------------------------------------------------------------------

    @Test
    fun launchIntentIsHandledOnce() {
        assertTrue(shouldHandleLaunchIntent(hasSavedInstanceState = false, intentFlags = 0))
        assertFalse(shouldHandleLaunchIntent(hasSavedInstanceState = true, intentFlags = 0))
        assertFalse(
            shouldHandleLaunchIntent(
                hasSavedInstanceState = false,
                intentFlags = Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY or Intent.FLAG_ACTIVITY_NEW_TASK,
            ),
        )
    }

    @Test
    fun publicEnrollmentFlagIsOwnedByTheTask() {
        assertFalse(resetEnrollmentFlagOnActivityDestroy(isPublicPlatform = true))
        assertTrue(resetEnrollmentFlagOnActivityDestroy(isPublicPlatform = false))
    }

    // --- APP-L17 -----------------------------------------------------------------------------

    @Test
    fun onlyExpectedIntentsCarryABootstrap() {
        assertEquals(ExternalBootstrapExtra.SEND_TEXT, externalBootstrapExtra(Intent.ACTION_SEND, "text/plain"))
        assertEquals(ExternalBootstrapExtra.NONE, externalBootstrapExtra(Intent.ACTION_SEND, "image/png"))
        assertEquals(ExternalBootstrapExtra.VIEW, externalBootstrapExtra(Intent.ACTION_VIEW, null))
        assertEquals(ExternalBootstrapExtra.NONE, externalBootstrapExtra(Intent.ACTION_MAIN, null))
        assertEquals(ExternalBootstrapExtra.NONE, externalBootstrapExtra(null, null))
    }

    @Test
    fun batteryHintNeedsTheInternalAlias() {
        assertTrue(isTrustedBatteryHintIntent(ACTION_OPEN_BATTERY_HINT, BATTERY_HINT_ALIAS_CLASS))
        assertFalse(isTrustedBatteryHintIntent(ACTION_OPEN_BATTERY_HINT, "pro.trafficwrapper.MainActivity"))
        assertFalse(isTrustedBatteryHintIntent(Intent.ACTION_MAIN, BATTERY_HINT_ALIAS_CLASS))
    }

    @Test
    fun malformedExtrasDoNotCrash() {
        val value: String? = readIntentExtrasSafely { throw RuntimeException("BadParcelableException") }
        assertNull(value)
        assertEquals("ok", readIntentExtrasSafely { "ok" })
    }

    // --- APP-L18 -----------------------------------------------------------------------------

    @Test
    fun permanentlyDeniedNotificationsOpenSettings() {
        fun action(requestedBefore: Boolean, rationale: Boolean, granted: Boolean = false, activity: Boolean = true) =
            notificationPermissionAction(
                sdkInt = 34,
                granted = granted,
                canRequestInActivity = activity,
                requestedBefore = requestedBefore,
                shouldShowRationale = rationale,
            )
        assertEquals(NotificationPermissionAction.REQUEST, action(requestedBefore = false, rationale = false))
        assertEquals(NotificationPermissionAction.REQUEST, action(requestedBefore = true, rationale = true))
        assertEquals(NotificationPermissionAction.OPEN_SETTINGS, action(requestedBefore = true, rationale = false))
        assertEquals(NotificationPermissionAction.OPEN_SETTINGS, action(requestedBefore = false, rationale = false, activity = false))
        assertEquals(NotificationPermissionAction.NONE, action(requestedBefore = true, rationale = false, granted = true))
    }

    // --- APP-M21 / APP-L17 manifest ----------------------------------------------------------

    @Test
    fun manifestLetsTheSplitTunnelPickerSeeLauncherApps() {
        val manifest = File("src/main/AndroidManifest.xml").readText()
        val queries = manifest.substringAfter("<queries>").substringBefore("</queries>")
        assertTrue(queries.contains("android.intent.action.MAIN"))
        assertTrue(queries.contains("android.intent.category.LAUNCHER"))
        val alias = manifest.substringAfter("<activity-alias").substringBefore("/>")
        assertTrue(alias.contains("android:name=\".BatteryHintActivity\""))
        assertTrue(alias.contains("android:exported=\"false\""))
        assertEquals("pro.trafficwrapper.BatteryHintActivity", BATTERY_HINT_ALIAS_CLASS)
    }

    private fun platformA(token: String, expires: String = "2035-01-01T00:00:00Z"): String =
        """{"orchestrator_url":"https://orch-a.dev","config_pubkey_pin":"pin-a","orch_noise_public":"noise-a","seed_workers":["https://worker-a.dev/tw/v1"],"bootstrap_token":"$token","expires":"$expires"}"""

    private fun platformB(): String =
        """{"orchestrator_url":"https://orch-b.dev","config_pubkey_pin":"pin-b","orch_noise_public":"noise-b","bootstrap_token":"token-b","expires":"2035-01-01T00:00:00Z"}"""
}
