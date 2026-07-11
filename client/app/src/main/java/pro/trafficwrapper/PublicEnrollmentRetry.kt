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

internal fun publicEnrollmentFailurePolicy(error: Throwable): PublicEnrollmentFailurePolicy {
    val causes = generateSequence(error) { it.cause }.toList()
    val message = causes.joinToString(" ") { it.message.orEmpty() }.lowercase(Locale.ROOT)
    val kind = when {
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
