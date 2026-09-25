package pro.trafficwrapper

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.time.Instant

/**
 * Contract between the orchestrator's buildAPKManifest (server-signed `apk-update-v1` manifests,
 * canonical JSON with sorted keys) and the client parser/policy (APP-M5).
 */
class UpdateManifestContractTest {
    private val apkSha = "a".repeat(64)
    private val certSha = "0123456789abcdef".repeat(4)
    private val keytoolCertPin = certSha.uppercase().chunked(2).joinToString(":")
    private val issuedAt = "2026-09-25T10:00:00Z"
    private val expiresAt = "2026-12-24T10:00:00Z"

    /** buildAPKManifest output per contract: expires_at always, signing_cert_sha256 omitted. */
    private val orchestratorFixtureWithoutCert =
        """{"apk_name":"app-public-32.apk","apk_sha256":"$apkSha","apk_size":12345678,""" +
            """"apk_url":"app-public-32.apk","expires_at":"$expiresAt","issued_at":"$issuedAt",""" +
            """"min_version":0,"ns":"apk-update-v1","notes":"Bug fixes","schema":1,"seq":7,""" +
            """"version_code":32,"version_name":"0.1.32"}"""

    /** buildAPKManifest output when the certificate digest was computed from the v2 signature. */
    private val orchestratorFixtureWithCert =
        """{"apk_name":"app-public-32.apk","apk_sha256":"$apkSha","apk_size":12345678,""" +
            """"apk_url":"app-public-32.apk","expires_at":"$expiresAt","issued_at":"$issuedAt",""" +
            """"min_version":0,"ns":"apk-update-v1","notes":"Bug fixes","schema":1,"seq":7,""" +
            """"signing_cert_sha256":"$certSha","version_code":32,"version_name":"0.1.32"}"""

    /** buildAPKManifest output before the orchestrator fix (no expires_at). */
    private val legacyOrchestratorFixture =
        """{"apk_name":"app-public-32.apk","apk_sha256":"$apkSha","apk_size":12345678,""" +
            """"apk_url":"app-public-32.apk","issued_at":"$issuedAt","min_version":0,""" +
            """"ns":"apk-update-v1","notes":"","schema":1,"seq":7,"version_code":32,"version_name":"0.1.32"}"""

    private val nowMs = Instant.parse("2026-09-25T11:00:00Z").toEpochMilli()

    private fun evaluate(raw: String, pin: String): ManifestDecision {
        val manifest = parseUpdateManifest(raw, pin)
        return evaluateUpdateManifest(
            manifest = manifest,
            pinnedSigningCertSha256 = pin,
            trustedNowMs = nowMs,
            futureReferenceMs = nowMs,
            currentVersionCode = 31,
            maxSeenUpdateSeq = 6,
        )
    }

    @Test
    fun orchestratorManifestWithoutCertUsesPinnedCertificate() {
        val manifest = parseUpdateManifest(orchestratorFixtureWithoutCert, certSha)
        assertEquals(certSha, manifest.signingCertSha256)
        assertEquals(32L, manifest.versionCode)
        assertEquals(12_345_678L, manifest.apkSize)
        assertEquals(apkSha, manifest.sha256)
        assertEquals(issuedAt, manifest.timestamp)
        assertEquals(expiresAt, manifest.expiresAt)
        assertEquals("app-public-32.apk", manifest.apkUrl)
        val decision = evaluate(orchestratorFixtureWithoutCert, certSha)
        assertTrue(decision is ManifestDecision.Available)
    }

    @Test
    fun orchestratorManifestWithCertPassesVerification() {
        val decision = evaluate(orchestratorFixtureWithCert, certSha)
        assertTrue(decision is ManifestDecision.Available)
        assertEquals(certSha, (decision as ManifestDecision.Available).manifest.signingCertSha256)
    }

    @Test
    fun keytoolFormattedPinIsNormalized() {
        assertTrue(evaluate(orchestratorFixtureWithCert, keytoolCertPin) is ManifestDecision.Available)
        assertTrue(evaluate(orchestratorFixtureWithoutCert, keytoolCertPin) is ManifestDecision.Available)
        assertEquals(certSha, normalizeCertSha256(keytoolCertPin))
    }

    @Test
    fun explicitNullOrEmptyCertFallsBackToPin() {
        val withNull = orchestratorFixtureWithCert.replace("\"$certSha\"", "null")
        val withEmpty = orchestratorFixtureWithCert.replace("\"$certSha\"", "\"\"")
        assertEquals(certSha, parseUpdateManifest(withNull, certSha).signingCertSha256)
        assertEquals(certSha, parseUpdateManifest(withEmpty, certSha).signingCertSha256)
    }

    @Test
    fun foreignCertificateIsRejected() {
        assertRejected(R.string.update_error_signer) { evaluate(orchestratorFixtureWithCert, "f".repeat(64)) }
    }

    @Test
    fun manifestWithoutExpiresAtIsRejected() {
        assertRejected(R.string.update_error_manifest) { parseUpdateManifest(legacyOrchestratorFixture, certSha) }
    }

    @Test
    fun rollbackAndExpiryAreStillEnforced() {
        val manifest = parseUpdateManifest(orchestratorFixtureWithoutCert, certSha)
        assertRejected(R.string.update_error_downgrade) {
            evaluateUpdateManifest(manifest, certSha, nowMs, nowMs, 31, maxSeenUpdateSeq = 8)
        }
        val afterExpiry = Instant.parse("2026-12-25T00:00:00Z").toEpochMilli()
        assertRejected(R.string.update_error_expired) {
            evaluateUpdateManifest(manifest, certSha, afterExpiry, afterExpiry, 31, 0)
        }
        // A re-issued manifest with a new seq for the same APK is accepted.
        assertTrue(evaluateUpdateManifest(manifest, certSha, nowMs, nowMs, 31, 7) is ManifestDecision.Available)
        assertTrue(evaluateUpdateManifest(manifest, certSha, nowMs, nowMs, 32, 7) is ManifestDecision.Latest)
    }

    @Test
    fun laggingTrustedClockDoesNotRejectFreshManifestAsFuture() {
        // APP-M23: an anchor 20 days behind must not turn a fresh manifest into "from the future"
        // when the system clock is sane.
        val manifest = parseUpdateManifest(orchestratorFixtureWithoutCert, certSha)
        val laggingTrusted = nowMs - 20L * 24 * 60 * 60 * 1000
        val decision = evaluateUpdateManifest(manifest, certSha, laggingTrusted, nowMs, 31, 0)
        assertTrue(decision is ManifestDecision.Available)
        assertRejected(R.string.update_error_time_untrusted) {
            evaluateUpdateManifest(manifest, certSha, laggingTrusted, laggingTrusted, 31, 0)
        }
    }

    @Test
    fun apkIdentityMustMatchManifest() {
        assertTrue(updateApkIdentityMatches("org.trafficwrapper.app", 32, "org.trafficwrapper.app", 32))
        assertTrue(!updateApkIdentityMatches("org.trafficwrapper.app", 31, "org.trafficwrapper.app", 32))
        assertTrue(!updateApkIdentityMatches("org.other.app", 32, "org.trafficwrapper.app", 32))
        assertTrue(!updateApkIdentityMatches(null, null, "org.trafficwrapper.app", 32))
    }

    private fun assertRejected(textRes: Int, block: () -> Unit) {
        try {
            block()
            fail("expected UpdateVerificationException")
        } catch (error: UpdateVerificationException) {
            assertEquals(textRes, error.textRes)
        }
    }
}
