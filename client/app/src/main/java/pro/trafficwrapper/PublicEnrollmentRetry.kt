package pro.trafficwrapper

import androidx.annotation.StringRes
import java.io.IOException
import java.util.Locale
import java.util.concurrent.TimeoutException

internal enum class PublicEnrollmentFailureKind {
    TRANSIENT,
    PENDING,
    BLOCKED,
    TERMINAL,
}

internal data class PublicEnrollmentFailurePolicy(
    val kind: PublicEnrollmentFailureKind,
    @StringRes val statusTextRes: Int,
    @StringRes val errorTextRes: Int?,
    val retryAllowed: Boolean,
)

/**
 * An ok=false enroll answer. [authenticated] is true when the Go core decrypted it from the Noise
 * channel (result "rejected": true); [code] is the orchestrator's structured code, blank for an
 * older orchestrator.
 */
internal class PublicEnrollmentRejectedException(
    val code: String,
    val authenticated: Boolean,
    message: String,
) : IllegalStateException(message)

/** Kind of a structured enroll rejection code; unknown codes are retryable (APP-L23). */
internal fun publicEnrollmentKindForCode(code: String): PublicEnrollmentFailureKind =
    when (code.trim().lowercase(Locale.ROOT)) {
        "device_not_approved" -> PublicEnrollmentFailureKind.PENDING
        "device_revoked" -> PublicEnrollmentFailureKind.BLOCKED
        "token_invalid", "token_expired", "token_exhausted",
        "identity_mismatch", "noise_mismatch", "awg_key_mismatch",
        -> PublicEnrollmentFailureKind.TERMINAL
        else -> PublicEnrollmentFailureKind.TRANSIENT
    }

/** The failure kind decided by the orchestrator itself (authenticated), or null. */
internal fun authenticatedPublicEnrollmentKind(error: Throwable): PublicEnrollmentFailureKind? {
    val rejected = generateSequence(error) { it.cause }
        .filterIsInstance<PublicEnrollmentRejectedException>()
        .firstOrNull { it.authenticated } ?: return null
    return publicEnrollmentFailurePolicy(rejected).kind
}

internal fun publicEnrollmentFailurePolicy(error: Throwable): PublicEnrollmentFailurePolicy {
    val causes = generateSequence(error) { it.cause }.toList()
    val message = causes.joinToString(" ") { it.message.orEmpty() }.lowercase(Locale.ROOT)
    if (causes.any { it is PublicClockSkewException }) {
        // Expired by the device clock only: fixing the clock (or a new bootstrap) helps (APP-L27).
        return PublicEnrollmentFailurePolicy(
            kind = PublicEnrollmentFailureKind.TRANSIENT,
            statusTextRes = R.string.enrollment_status_error,
            errorTextRes = R.string.public_enrollment_error_clock,
            retryAllowed = true,
        )
    }
    val coded = causes.filterIsInstance<PublicEnrollmentRejectedException>()
        .firstOrNull { it.authenticated && it.code.isNotBlank() }
    val kind = when {
        // A structured code from inside the Noise channel wins; text is only the fallback for an
        // orchestrator that predates "code".
        coded != null -> publicEnrollmentKindForCode(coded.code)
        // Text sent outside the Noise channel never decides pending/blocked/terminal (APP-L22).
        PUBLIC_ENROLLMENT_UNAUTHENTICATED_MARKER in message -> PublicEnrollmentFailureKind.TRANSIENT
        PUBLIC_ENROLLMENT_PENDING_MARKERS.any(message::contains) -> PublicEnrollmentFailureKind.PENDING
        PUBLIC_ENROLLMENT_BLOCKED_MARKERS.any(message::contains) -> PublicEnrollmentFailureKind.BLOCKED
        PUBLIC_ENROLLMENT_TERMINAL_MARKERS.any(message::contains) -> PublicEnrollmentFailureKind.TERMINAL
        causes.any { it is IOException || it is TimeoutException } ||
            PUBLIC_ENROLLMENT_TRANSIENT_MARKERS.any(message::contains) -> PublicEnrollmentFailureKind.TRANSIENT
        else -> PublicEnrollmentFailureKind.TERMINAL
    }
    return when (kind) {
        PublicEnrollmentFailureKind.TRANSIENT -> PublicEnrollmentFailurePolicy(
            kind = kind,
            statusTextRes = R.string.enrollment_status_error,
            errorTextRes = R.string.public_enrollment_error,
            retryAllowed = true,
        )
        PublicEnrollmentFailureKind.PENDING -> PublicEnrollmentFailurePolicy(
            kind = kind,
            statusTextRes = R.string.enrollment_status_pending,
            errorTextRes = null,
            retryAllowed = false,
        )
        PublicEnrollmentFailureKind.BLOCKED -> PublicEnrollmentFailurePolicy(
            kind = kind,
            statusTextRes = R.string.enrollment_status_blocked,
            errorTextRes = R.string.public_enrollment_terminal_error,
            retryAllowed = false,
        )
        PublicEnrollmentFailureKind.TERMINAL -> PublicEnrollmentFailurePolicy(
            kind = kind,
            statusTextRes = R.string.enrollment_status_error,
            errorTextRes = R.string.public_enrollment_terminal_error,
            retryAllowed = false,
        )
    }
}

internal fun publicEnrollmentFailureState(
    current: AuthUiState,
    policy: PublicEnrollmentFailurePolicy,
): AuthUiState = current.copy(
    authorized = false,
    inProgress = false,
    enrollmentRetryAllowed = policy.retryAllowed,
    statusTextRes = policy.statusTextRes,
    errorTextRes = policy.errorTextRes,
)

internal fun retryPublicEnrollmentIfAllowed(
    auth: AuthUiState,
    bootstrapRaw: String,
    enroll: (String) -> Unit,
): Boolean {
    if (auth.authorized || auth.inProgress || !auth.enrollmentRetryAllowed || bootstrapRaw.isBlank()) return false
    enroll(bootstrapRaw)
    return true
}

/** Prefix of every error text the core received outside the Noise channel (untrustedServerPrefix). */
private const val PUBLIC_ENROLLMENT_UNAUTHENTICATED_MARKER = "unauthenticated server response"

/**
 * Exponential backoff for enrollment attempts that start without an explicit user action
 * (activity start, background re-enrollment). Times are SystemClock.elapsedRealtime().
 */
internal class PublicEnrollmentBackoff(
    private val minDelayMs: Long = PUBLIC_ENROLL_BACKOFF_MIN_MS,
    private val maxDelayMs: Long = PUBLIC_ENROLL_BACKOFF_MAX_MS,
) {
    private var failures = 0
    private var notBeforeMs = 0L

    @Synchronized
    fun remainingMs(nowMs: Long): Long = if (failures == 0) 0L else (notBeforeMs - nowMs).coerceAtLeast(0L)

    @Synchronized
    fun onFailure(nowMs: Long) {
        failures = (failures + 1).coerceAtMost(MAX_SHIFT)
        val delay = (minDelayMs shl (failures - 1)).coerceIn(minDelayMs, maxDelayMs)
        notBeforeMs = nowMs + delay
    }

    @Synchronized
    fun onSuccess() {
        failures = 0
        notBeforeMs = 0L
    }

    private companion object {
        const val MAX_SHIFT = 20
    }
}

internal const val PUBLIC_ENROLL_BACKOFF_MIN_MS = 30_000L
internal const val PUBLIC_ENROLL_BACKOFF_MAX_MS = 60 * 60_000L

/**
 * Rate limit for confirming an unauthenticated "device not approved" hint (worker poll or
 * telemetry) with a Noise re-enrollment: at most one confirmation per [intervalMs].
 */
internal class PublicReauthConfirmThrottle(private val intervalMs: Long = PUBLIC_REAUTH_CONFIRM_INTERVAL_MS) {
    private var lastAtMs = Long.MIN_VALUE

    @Synchronized
    fun tryAcquire(nowMs: Long): Boolean {
        if (lastAtMs != Long.MIN_VALUE && nowMs - lastAtMs in 0 until intervalMs) return false
        lastAtMs = nowMs
        return true
    }
}

internal const val PUBLIC_REAUTH_CONFIRM_INTERVAL_MS = 10 * 60_000L

/** Why a background (silent) re-enrollment is wanted. */
internal enum class PublicReEnrollReason {
    /** The cached enrollment was made by another app version (capabilities changed). */
    VERSION_REFRESH,

    /** The orchestrator announced reality_flow_pending: acknowledge it (two-phase Vision). */
    FLOW_ACK,

    /** The client bundle names an AWG profile this device holds no credentials for (X-M4). */
    AWG_PROFILE_CREDENTIALS,

    /** A worker said "device not approved" outside the Noise channel: confirm it (APP-L8). */
    REAUTH_CONFIRM,
}

internal sealed class PublicReEnrollPlan {
    data class Wait(val delayMs: Long) : PublicReEnrollPlan()
    data class Run(val viaTunnel: Boolean) : PublicReEnrollPlan()
    object Idle : PublicReEnrollPlan()
}

/**
 * Background re-enrollment runs through the tunnel (APP-M4) and waits for one when none carries
 * traffic. The only exception is confirming a revocation hint - a revoked device has no tunnel -
 * which may go direct, still under the backoff and the confirmation throttle.
 */
internal fun publicReEnrollPlan(
    reasons: Set<PublicReEnrollReason>,
    tunnelUp: Boolean,
    backoffRemainingMs: Long,
    checkIntervalMs: Long = PUBLIC_REENROLL_CHECK_INTERVAL_MS,
): PublicReEnrollPlan =
    when {
        reasons.isEmpty() -> PublicReEnrollPlan.Idle
        backoffRemainingMs > 0 -> PublicReEnrollPlan.Wait(backoffRemainingMs)
        tunnelUp -> PublicReEnrollPlan.Run(viaTunnel = true)
        PublicReEnrollReason.REAUTH_CONFIRM in reasons -> PublicReEnrollPlan.Run(viaTunnel = false)
        else -> PublicReEnrollPlan.Wait(checkIntervalMs)
    }

internal const val PUBLIC_REENROLL_CHECK_INTERVAL_MS = 15_000L

private val PUBLIC_ENROLLMENT_PENDING_MARKERS = listOf(
    "device is not approved",
    "device_not_approved",
    "owner approval required",
)

private val PUBLIC_ENROLLMENT_BLOCKED_MARKERS = listOf(
    "device revoked",
    "device blocked",
    "identity revoked",
    "access revoked",
    "access blocked",
)

private val PUBLIC_ENROLLMENT_TERMINAL_MARKERS = listOf(
    "device identity mismatch",
    "device noise pub mismatch",
    "device awg public key mismatch",
    "bootstrap token",
    "bootstrap expired",
    "invalid bootstrap",
    "identity_pubkey is required",
    "awg_public_key is required",
    "request is incomplete",
    "missing client bundle",
    "config public key",
    "signature",
    "rollback",
    "downgrade",
    "no usable route",
)

private val PUBLIC_ENROLLMENT_TRANSIENT_MARKERS = listOf(
    "timeout",
    "timed out",
    "deadline exceeded",
    "connection refused",
    "connection reset",
    "connection closed",
    "dial tcp",
    "dial udp",
    "lookup ",
    "no such host",
    "network is unreachable",
    "no route to host",
    "temporary",
    "unavailable",
    "eof",
    "broken pipe",
    "bad gateway",
    "internal server error",
    "too many requests",
    "rate limit",
    "noise session limit",
    "noise session expired",
    "noise decrypt failed",
    "no approved worker",
    "signer unavailable",
    "tls handshake",
    "http 429",
    "http 502",
    "http 503",
    "http 504",
)
