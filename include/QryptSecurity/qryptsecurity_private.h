#ifndef QRYPTSECURITY_PRIVATE_H
#define QRYPTSECURITY_PRIVATE_H


namespace QryptSecurity {

/// <summary>
/// Enumeration of cloud environments
/// </summary>
enum class FQDN_ENV {
    /// <summary>
    /// Production environment
    /// </summary>
    FQDN_ENV_PROD,

    /// <summary>
    /// Staging environment
    /// </summary>
    FQDN_ENV_STAGING,

    /// <summary>
    /// Development environment
    /// </summary>
    FQDN_ENV_DEV,

    /// <summary>
    /// Number of cloud environments
    /// </summary>
    NUM_FQDN_ENV
};

/// <summary>
/// Set RPS cloud environment
/// </summary>
///
/// <param name="env">Cloud environment</param>
void setRpsEnv(FQDN_ENV env);

/// <summary>
/// Set BLAST cloud environment
/// </summary>
///
/// <param name="env">Cloud environment</param>
void setBlastEnv(FQDN_ENV env);

} // namespace

#endif
