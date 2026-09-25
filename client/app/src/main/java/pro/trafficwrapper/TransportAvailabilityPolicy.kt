package pro.trafficwrapper

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream

/*
 * Pure availability policies of the transport worker (AutoTransportService), kept free of
 * Android types so they can be unit tested on the JVM.
 */

/** Inactive TCP route while the active route is unhealthy: keep it warm and probe it often. */
internal const val TCP_STANDBY_PROBE_INTERVAL_MS = 5_000L

/** Inactive TCP route while the active route is healthy: rare probes, no local traffic needed. */
internal const val TCP_STANDBY_HEALTHY_ACTIVE_PROBE_INTERVAL_MS = 75_000L

/** Consecutive successful probes that count as a completed dwell for a TCP route. */
internal const val TCP_DWELL_MIN_CONSECUTIVE_PROBES = 3

/**
 * Whether a REALITY/REALITY2 route is due for a probe. The active route is probed every
 * [activeIntervalMs]. An inactive route is probed every [TCP_STANDBY_PROBE_INTERVAL_MS] while the
 * active route is unhealthy (so a failover target stays fresh and can complete its dwell), and
 * every [TCP_STANDBY_HEALTHY_ACTIVE_PROBE_INTERVAL_MS] otherwise, whether or not it carried
 * local traffic.
 */
internal fun shouldProbeTcpRoute(
    nowMs: Long,
    lastProbeAtMs: Long,
    routeIsActive: Boolean,
    activeRouteHealthy: Boolean,
    activeIntervalMs: Long = PROBE_INTERVAL_MS,
): Boolean {
    if (lastProbeAtMs == 0L) return true
    val intervalMs = when {
        routeIsActive -> activeIntervalMs
        activeRouteHealthy -> TCP_STANDBY_HEALTHY_ACTIVE_PROBE_INTERVAL_MS
        else -> TCP_STANDBY_PROBE_INTERVAL_MS
    }
    return nowMs - lastProbeAtMs >= intervalMs
}

/**
 * Dwell of a TCP route: continuously healthy for [dwellMs], or [minConsecutiveProbes] successful
 * probes in a row (probe results stay valid for a shorter time than the dwell when the route is
 * probed rarely).
 */
internal fun tcpRouteDwelled(
    healthySinceMs: Long,
    consecutiveOkProbes: Int,
    nowMs: Long,
    dwellMs: Long,
    minConsecutiveProbes: Int = TCP_DWELL_MIN_CONSECUTIVE_PROBES,
): Boolean =
    (healthySinceMs > 0L && nowMs - healthySinceMs >= dwellMs) || consecutiveOkProbes >= minConsecutiveProbes

/**
 * A single stalled session (for example to one destination that silently drops traffic) does
 * not make a route stalled while other sessions still receive data; several stalled
 * destinations, or a stall without any downlink progress, do.
 */
internal fun tcpUserSessionsIndicateStall(
    stalledDestinations: Int,
    hasRecentUserDownlinkProgress: Boolean,
): Boolean =
    stalledDestinations >= TCP_STALL_MIN_DESTINATIONS ||
        (stalledDestinations > 0 && !hasRecentUserDownlinkProgress)

internal const val TCP_STALL_MIN_DESTINATIONS = 2

/** Guard for demoting the active TCP route after a stall (same rule as for inactive routes). */
internal fun shouldDemoteActiveTcpRouteAfterStallGuarded(
    rxStalled: Boolean,
    routeIsActive: Boolean,
    hasRecentUserDownlinkProgress: Boolean,
    stalledDestinations: Int,
): Boolean =
    rxStalled &&
        routeIsActive &&
        (!hasRecentUserDownlinkProgress || stalledDestinations >= TCP_STALL_MIN_DESTINATIONS)

/**
 * Lifecycle/network events waiting for the worker. Events accumulate instead of overwriting each
 * other, and the disruptive flag is sticky: a harmless event (screen on) arriving after a network
 * switch cannot hide the switch.
 */
internal class PendingLifecycleEvents<E : Any>(private val isDisruptive: (E) -> Boolean) {
    private val events = LinkedHashSet<E>()

    @Synchronized
    fun add(event: E) {
        events.remove(event)
        events.add(event)
    }

    @Synchronized
    fun isPending(): Boolean = events.isNotEmpty()

    @Synchronized
    fun clear() {
        events.clear()
    }

    /** Takes every pending event; null when nothing is pending. */
    @Synchronized
    fun drain(): LifecycleEventBatch<E>? {
        if (events.isEmpty()) return null
        val batch = LifecycleEventBatch(events.toList(), events.any(isDisruptive))
        events.clear()
        return batch
    }
}

internal data class LifecycleEventBatch<E>(val events: List<E>, val marksTunnelDisruption: Boolean)

/** Whether the backstop alarm scheduled for [scheduledAtMs] can stay (it is not later than wanted). */
internal fun shouldKeepScheduledBackstop(scheduledAtMs: Long, nowMs: Long, intervalMs: Long): Boolean =
    scheduledAtMs > nowMs && scheduledAtMs - nowMs <= intervalMs

/**
 * RX progress that counts as tunnel activity for the probe cadence: progress observed in a cycle
 * in which the worker itself generated traffic (probes, config poll) is not user activity; RX of
 * user sessions seen by the router always is.
 */
internal fun idleSignalRxAtMs(
    previousMs: Long,
    nowMs: Long,
    rxAdvanced: Boolean,
    selfTrafficInCycle: Boolean,
    userTrafficAtMs: Long,
): Long =
    maxOf(previousMs, if (rxAdvanced && !selfTrafficInCycle) nowMs else 0L, userTrafficAtMs)

/** How old a route health snapshot may be to still describe the tunnel, given the planned sleep. */
internal fun routeSnapshotMaxAgeMs(plannedSleepMs: Long): Long =
    maxOf(STABLE_TRAFFIC_MAX_AGE_MS, plannedSleepMs + ROUTE_SNAPSHOT_SLEEP_GRACE_MS)

internal const val ROUTE_SNAPSHOT_SLEEP_GRACE_MS = 5_000L

/** A state computed by worker [publishGeneration] may be shown only while that worker is current. */
internal fun shouldPublishWorkerState(publishGeneration: Long?, currentGeneration: Long, workerActive: Boolean): Boolean =
    publishGeneration == null || (workerActive && publishGeneration == currentGeneration)

/** Generation the active upstream must carry after the sidecar on [restartedPort] was restarted. */
internal fun activeUpstreamGenerationAfterRestart(
    activePort: Int,
    activeGeneration: Long,
    restartedPort: Int,
    restartedGeneration: Long,
): Long = if (activePort == restartedPort) restartedGeneration else activeGeneration

/** Reads the whole stream, failing once more than [limitBytes] arrive. */
internal fun readBodyWithLimit(input: InputStream, limitBytes: Int): ByteArray {
    val out = ByteArrayOutputStream(minOf(limitBytes, BOUNDED_READ_BUFFER_BYTES))
    val buffer = ByteArray(BOUNDED_READ_BUFFER_BYTES)
    while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        if (out.size() + read > limitBytes) throw IOException("response body exceeds $limitBytes bytes")
        out.write(buffer, 0, read)
    }
    return out.toByteArray()
}

/** Reads at most [limitBytes] and stops (the rest of the stream is left unread). */
internal fun readAtMostBytes(input: InputStream, limitBytes: Int): ByteArray {
    val out = ByteArrayOutputStream(minOf(limitBytes, BOUNDED_READ_BUFFER_BYTES))
    val buffer = ByteArray(BOUNDED_READ_BUFFER_BYTES)
    while (out.size() < limitBytes) {
        val read = input.read(buffer, 0, minOf(buffer.size, limitBytes - out.size()))
        if (read < 0) break
        out.write(buffer, 0, read)
    }
    return out.toByteArray()
}

private const val BOUNDED_READ_BUFFER_BYTES = 8 * 1024
