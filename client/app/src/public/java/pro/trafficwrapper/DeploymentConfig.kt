package pro.trafficwrapper

internal object DeploymentConfig {
    const val IS_PUBLIC_PLATFORM = true
    const val PROVISION_ADDR = ""
    const val PROVISION_SERVER_PUBLIC = ""
    const val SERVER_AWG_PUBLIC = ""
    const val SERVER_AWG_RU_PUBLIC = ""
    const val DEFAULT_REALITY_EGRESS_IP = ""
    const val DEFAULT_REALITY2_EGRESS_IP = ""
    // Egress echo used when the signed client bundle has no egress_probe_urls; when both are
    // empty the app falls back to api.ipify.org (see egressProbeUrls in AutoTransportService).
    const val OUTBOUND_URL = ""
    const val PUBLIC_UPDATE_BASE_URL = ""
}
