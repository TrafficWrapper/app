package pro.trafficwrapper

import android.content.Intent
import java.util.concurrent.atomic.AtomicLong

/*
 * Pure decisions behind the MainActivity UX fixes of review 2026-09-25 (group W4). They are kept
 * free of Android runtime calls so they can be covered by plain JVM unit tests.
 */

/**
 * APP-M11: a user connect request that is carried out later (after an async restore or key
 * request) must not start the transport once the user pressed Cancel/Disconnect in between.
 * Every explicit stop bumps the generation; a deferred start runs only if its token is current.
 */
internal class ConnectRequestGate {
    private val generation = AtomicLong(0L)

    /** Token of the connect request being issued now. */
    fun begin(): Long = generation.get()

    /** Explicit stop/cancel: every connect request issued before is void. */
    fun cancel() {
        generation.incrementAndGet()
    }

    fun isCurrent(token: Long): Boolean = generation.get() == token
}

/*
 * APP-M12 / APP-L14 / APP-L20: the bootstrap lives only in the sealed public platform state.
 * [StoredPublicPlatformState.bootstrapRaw] is the bootstrap of the last successful enrollment
 * (active); [StoredPublicPlatformState.pendingBootstrapRaw] is one the user imported, confirmed or
 * refreshed that has not been enrolled yet. Every writer goes through these functions.
 */

/**
 * The bootstrap an enrollment should use. A user-visible (non-silent) enrollment prefers the
 * pending bootstrap; a silent re-enrollment of the enrolled platform uses the pending one only when
 * it belongs to the same platform (a refreshed token), never a not yet confirmed switch.
 */
internal fun publicBootstrapForEnrollment(state: StoredPublicPlatformState, silent: Boolean): String {
    val active = state.bootstrapRaw.trim()
    val pending = state.pendingBootstrapRaw.trim()
    if (pending.isEmpty()) return active
    if (!silent || active.isEmpty()) return pending
    return if (publicBootstrapsSamePlatform(active, pending)) pending else active
}

/** Records [raw] as the pending bootstrap; a bootstrap equal to the active one clears it. */
internal fun withPendingPublicBootstrap(state: StoredPublicPlatformState, raw: String): StoredPublicPlatformState {
    val trimmed = raw.trim()
    return state.copy(pendingBootstrapRaw = if (trimmed == state.bootstrapRaw.trim()) "" else trimmed)
}

/**
 * Pending bootstrap after an enrollment with [usedRaw] succeeded: cleared only when it is the one
 * that was enrolled. A bootstrap confirmed while the enrollment was running survives (APP-L14).
 */
internal fun pendingPublicBootstrapAfterEnrollment(currentPending: String, usedRaw: String): String =
    if (currentPending.trim() == usedRaw.trim()) "" else currentPending.trim()

/**
 * Moves a legacy plain SharedPreferences copy of the bootstrap into the sealed state (APP-L20).
 * Returns null when nothing has to be written.
 */
internal fun migrateLegacyPublicBootstrap(
    state: StoredPublicPlatformState,
    legacyRaw: String,
): StoredPublicPlatformState? {
    val legacy = legacyRaw.trim()
    if (legacy.isEmpty()) return null
    if (legacy == state.bootstrapRaw.trim() || legacy == state.pendingBootstrapRaw.trim()) return null
    if (state.pendingBootstrapRaw.isNotBlank()) return null
    return withPendingPublicBootstrap(state, legacy)
}

/** Two bootstraps point at the same platform: every trusted field matches (expiry ignored). */
internal fun publicBootstrapsSamePlatform(currentRaw: String, incomingRaw: String): Boolean {
    val current = parseBootstrapIgnoringExpiry(currentRaw) ?: return false
    val incoming = parseBootstrapIgnoringExpiry(incomingRaw) ?: return false
    return publicBootstrapTrustedFieldsMatch(current, incoming)
}

/**
 * Parses a stored bootstrap without the expiry check (APP-L12): an expired stored bootstrap still
 * names the platform the device uses, so comparisons and the replace dialog must see it.
 */
internal fun parseBootstrapIgnoringExpiry(raw: String): PublicBootstrapConfig? =
    raw.takeIf { it.isNotBlank() }?.let {
        runCatching { PublicPlatformConfigParser.parseBootstrap(it, nowMs = 0L) }.getOrNull()
    }

/**
 * APP-M13: "import another bootstrap" drops the pending bootstrap; without a sealed enrollment the
 * stored bootstrap goes too, so the next start shows the import screen instead of retrying it.
 */
internal fun discardPendingPublicBootstrapState(state: StoredPublicPlatformState): StoredPublicPlatformState =
    if (state.clientBundleJson.isBlank()) {
        state.copy(pendingBootstrapRaw = "", bootstrapRaw = "")
    } else {
        state.copy(pendingBootstrapRaw = "")
    }

/** A refreshed token restarts the enrollment only from an idle (failed / waiting) state (APP-M12). */
internal fun shouldEnrollAfterBootstrapRefresh(auth: AuthUiState): Boolean =
    !auth.authorized && !auth.inProgress

/** APP-M13: after a failed enrollment the user can go back and import another bootstrap. */
internal fun showImportAnotherBootstrap(auth: AuthUiState): Boolean =
    !auth.authorized && !auth.inProgress && auth.errorTextRes != null

/**
 * APP-M14: routes the user can pick with this config. AUTO needs any route; a manual route needs
 * a priority entry and a usable slot.
 */
internal fun publicAvailableTransportChoices(slots: PublicPlatformRouteSlots): Set<TransportChoice> {
    val priorities = slots.routePriorities
    val available = mutableSetOf<TransportChoice>()
    if (priorities.isNotEmpty() || slots.hasUsableRoute()) available += TransportChoice.AUTO
    if (priorities.containsKey("AWG_RU") && slots.awgRu != null) available += TransportChoice.AWG_RU
    if (priorities.containsKey("AWG") && slots.awg != null) available += TransportChoice.AWG
    if (priorities.containsKey("REALITY") && slots.reality?.isComplete() == true) available += TransportChoice.REALITY
    if (priorities.containsKey("REALITY2") && slots.reality2?.isComplete() == true) {
        available += TransportChoice.REALITY2
    }
    return available
}

/**
 * APP-M14: the route selection survives a config apply. It is initialised once per process from
 * the remembered mode and falls back to AUTO only when the chosen route is not in the config.
 */
internal fun publicSelectedTransportAfterApply(
    current: TransportChoice,
    initialized: Boolean,
    preferred: TransportChoice,
    available: Set<TransportChoice>,
): TransportChoice {
    val candidate = if (initialized) current else preferred
    return if (candidate == TransportChoice.AUTO || candidate in available) candidate else TransportChoice.AUTO
}

/**
 * APP-M14: the persisted "approval required" flag after a successful enrollment. An orchestrator
 * answer that is not "pending" means the device is approved again; "pending" keeps the flag (it is
 * set only by [applyConfirmedPublicReauth], i.e. after the orchestrator confirmed it).
 */
internal fun publicReauthRequiredAfterEnrollment(current: Boolean, status: String): Boolean =
    current && status.trim().equals("pending", ignoreCase = true)

/** APP-L13: one trusted bootstrap field that the incoming bootstrap changes. */
internal data class BootstrapFieldChange(
    val field: String,
    val current: String,
    val incoming: String,
    /** Pins and keys: changing them hands trust to other keys and needs a second confirmation. */
    val keyMaterial: Boolean,
)

internal fun externalBootstrapTrustedFieldChanges(
    current: PublicBootstrapConfig?,
    incoming: PublicBootstrapConfig,
): List<BootstrapFieldChange> {
    fun change(field: String, old: String, new: String, keyMaterial: Boolean): BootstrapFieldChange? =
        if (old.trim() == new.trim()) null else BootstrapFieldChange(field, old.trim(), new.trim(), keyMaterial)
    val seedCurrent = current?.seedWorkers.orEmpty().map { it.trim() }.filter { it.isNotEmpty() }.sorted()
    val seedIncoming = incoming.seedWorkers.map { it.trim() }.filter { it.isNotEmpty() }.sorted()
    return listOfNotNull(
        change("orchestrator_url", current?.orchestratorUrl.orEmpty(), incoming.orchestratorUrl, keyMaterial = false),
        change("config_pubkey_pin", current?.configPubkeyPin.orEmpty(), incoming.configPubkeyPin, keyMaterial = true),
        change("orch_noise_public", current?.orchNoisePublic.orEmpty(), incoming.orchNoisePublic, keyMaterial = true),
        change("update_pubkey", current?.updatePubkey.orEmpty(), incoming.updatePubkey, keyMaterial = true),
        change(
            "orch_tls_spki_sha256",
            current?.orchTlsSpkiSha256.orEmpty().sorted().joinToString(", "),
            incoming.orchTlsSpkiSha256.sorted().joinToString(", "),
            keyMaterial = true,
        ),
        change("seed_workers", seedCurrent.joinToString(", "), seedIncoming.joinToString(", "), keyMaterial = false),
    )
}

/** APP-L13: replacing a platform's pins or keys takes a second, explicit confirmation. */
internal fun externalBootstrapNeedsSecondConfirmation(
    replacesExisting: Boolean,
    changes: List<BootstrapFieldChange>,
): Boolean = replacesExisting && changes.any { it.keyMaterial }

/**
 * APP-L15: the launch intent is handled once: not again when the activity is recreated from saved
 * state, and not when it is relaunched from recents (the original intent would be replayed).
 */
internal fun shouldHandleLaunchIntent(hasSavedInstanceState: Boolean, intentFlags: Int): Boolean =
    !hasSavedInstanceState && (intentFlags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) == 0

/**
 * APP-L16: the public enrollment task owns ENROLLMENT_ACTIVE and clears it itself; only the
 * private flavor's activity-scoped polling loop is stopped when the activity goes away.
 */
internal fun resetEnrollmentFlagOnActivityDestroy(isPublicPlatform: Boolean): Boolean = !isPublicPlatform

/** APP-L17: where an external bootstrap may come from for a given intent. */
internal enum class ExternalBootstrapExtra {
    NONE,

    /** ACTION_SEND text/plain: EXTRA_TEXT or the explicit payload extra. */
    SEND_TEXT,

    /** ACTION_VIEW: the twp://enroll deep link (and the explicit payload extra). */
    VIEW,
}

internal fun externalBootstrapExtra(action: String?, type: String?): ExternalBootstrapExtra =
    when (action) {
        Intent.ACTION_SEND ->
            if (type == null || type.equals("text/plain", ignoreCase = true)) {
                ExternalBootstrapExtra.SEND_TEXT
            } else {
                ExternalBootstrapExtra.NONE
            }
        Intent.ACTION_VIEW -> ExternalBootstrapExtra.VIEW
        else -> ExternalBootstrapExtra.NONE
    }

/**
 * APP-L17: the battery hint is honoured only when it arrives through the non-exported alias, i.e.
 * from this app's own notification, not from any app that can start the exported MainActivity.
 */
internal fun isTrustedBatteryHintIntent(action: String?, componentClassName: String?): Boolean =
    action == ACTION_OPEN_BATTERY_HINT && componentClassName == BATTERY_HINT_ALIAS_CLASS

internal const val BATTERY_HINT_ALIAS_CLASS = "pro.trafficwrapper.BatteryHintActivity"

/**
 * APP-L17: reads intent extras without letting a malformed or foreign Parcelable from another app
 * crash the process (and the VPN with it).
 */
internal inline fun <T> readIntentExtrasSafely(read: () -> T?): T? =
    try {
        read()
    } catch (_: Throwable) {
        null
    }

/** APP-L18: what the "enable notifications" action should do. */
internal enum class NotificationPermissionAction {
    NONE,
    REQUEST,
    OPEN_SETTINGS,
}

/**
 * After the user denied the permission for good the system dialog no longer appears
 * (shouldShowRequestPermissionRationale is false once it was requested before), so the app
 * notification settings are opened instead.
 */
internal fun notificationPermissionAction(
    sdkInt: Int,
    granted: Boolean,
    canRequestInActivity: Boolean,
    requestedBefore: Boolean,
    shouldShowRationale: Boolean,
): NotificationPermissionAction =
    when {
        granted -> NotificationPermissionAction.NONE
        sdkInt < 33 -> NotificationPermissionAction.OPEN_SETTINGS
        !canRequestInActivity -> NotificationPermissionAction.OPEN_SETTINGS
        requestedBefore && !shouldShowRationale -> NotificationPermissionAction.OPEN_SETTINGS
        else -> NotificationPermissionAction.REQUEST
    }
