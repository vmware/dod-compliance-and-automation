include_controls 'ubuntu'
# include_controls 'ubuntu' do
#   # These controls are N/A or not supported for NSX appliances. See the waivers-ubuntu.yml file for more details.
#   # NTP/Chrony - NTPD is used instead of Chrony
#   skip_control 'UBTU-24-100700'  # chrony package not installed
#   skip_control 'UBTU-24-100010'  # systemd-timesyncd is installed
#   skip_control 'UBTU-24-100020'  # ntp package is installed
#   skip_control 'UBTU-24-600160'  # chrony maxpoll NTP sync
#   skip_control 'UBTU-24-600180'  # chrony makestep sync
#   # Data at rest encryption - provided by underlying storage (vSAN)
#   skip_control 'UBTU-24-600090'  # data at rest encryption not enabled at OS level
#   # Firewall - iptables is used instead of UFW
#   skip_control 'UBTU-24-100310'  # UFW not enabled
#   skip_control 'UBTU-24-600200'  # UFW rate-limiting not configured
#   skip_control 'UBTU-24-300041'  # PPSM ports/protocols (see ports.broadcom.com)
#   # Session lock - session timeouts used instead of vlock
#   skip_control 'UBTU-24-101000'  # vlock not installed
#   # MFA - MFA to local OS unsupported on VCF appliances
#   skip_control 'UBTU-24-100650'  # SSSD packages not installed
#   skip_control 'UBTU-24-100660'  # SSSD service not running
#   skip_control 'UBTU-24-100900'  # opensc-pkcs11 not installed
#   skip_control 'UBTU-24-100910'  # libpam-pkcs11 not installed
#   skip_control 'UBTU-24-400020'  # pam_pkcs11.so smart card login not configured
#   skip_control 'UBTU-24-400030'  # PubkeyAuthentication SSH not configured for MFA
#   skip_control 'UBTU-24-400060'  # ocsp_on cert policy not configured
#   skip_control 'UBTU-24-400360'  # SSSD cert path validation not configured
#   skip_control 'UBTU-24-400370'  # identity mapping not configured
#   skip_control 'UBTU-24-400375'  # cert path validation (PAM) not configured
#   skip_control 'UBTU-24-400380'  # CRL revocation cache not configured
#   # PKI - DOD Root CAs not appropriate for all customers
#   skip_control 'UBTU-24-600060'  # DOD Root CAs not in trust store
#   # FIPS/Ubuntu Pro - Ubuntu Pro not available on VCF appliances
#   skip_control 'UBTU-24-600030'  # FIPS kernel not enabled
#   skip_control 'UBTU-24-700400'  # Ubuntu Pro subscription not available
# end
