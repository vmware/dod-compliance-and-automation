control 'UBTU-22-254010' do
  title 'Ubuntu 22.04 LTS must have the "SSSD" package installed.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include:
1) Something a user knows (e.g., password/PIN);
2) Something a user has (e.g., cryptographic identification device, token); and
3) Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

The DOD common access card (CAC) with DOD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify Ubuntu 22.04 LTS has the packages required for multifactor authentication installed with the following command:

$ dpkg -l | grep sssd
ii sssd 2.9.4-1.1ubuntu6.1 amd64 System Security Services Daemon -- metapackage
ii sssd-ad 2.9.4-1.1ubuntu6.1 amd64 System Security Services Daemon -- Active Directory back end
ii sssd-ad-common 2.9.4-1.1ubuntu6.1 amd64 System Security Services Daemon -- PAC responder
ii sssd-common 2.9.4-1.1ubuntu6.1 amd64 System Security Services Daemon -- common files
ii sssd-ipa 2.9.4-1.1ubuntu6.1 amd64 System Security Services Daemon -- IPA back end
ii sssd-krb5 2.9.4-1.1ubuntu6.1 amd64 System Security Services Daemon -- Kerberos back end
ii sssd-krb5-common 2.9.4-1.1ubuntu6.1 amd64 System Security Services Daemon -- Kerberos helpers
ii sssd-ldap 2.9.4-1.1ubuntu6.1 amd64 System Security Services Daemon -- LDAP back end
ii sssd-proxy 2.9.4-1.1ubuntu6.1 amd64 System Security Services Daemon -- proxy back end

If the "sssd" package is not installed, this is a finding. The additional sssd components listed by the command may differ from configuration to configuration.

Verify that "libpam-sss" (the PAM integration module for SSSD) is installed with the following command:

$ dpkg -l | grep libpam-sss
i libpam-sss:amd64 2.9.4-1.1ubuntu6.1 amd64 Pam module for the System Security Services Daemon

Verify that "libnss-sss" (the NSS module for retrieving user and group information) is installed with the following command:

$ dpkg -l | grep libnss-sss
ii libnss-sss:amd64 2.9.4-1.1ubuntu6.1 amd64 Nss library for the System Security Services Daemon

If "libpam-sss" and "libnss-sss" are not installed, this is a finding.'
  desc 'fix', 'Install the sssd.service and the required pam packages with the following commands:

$ sudo apt install sssd

$ sudo apt install libpam-sss

$ sudo apt install libnss-sss'
  impact 0.5
  tag check_id: 'C-78965r1155183_chk'
  tag severity: 'medium'
  tag gid: 'V-274864'
  tag rid: 'SV-274864r1155209_rule'
  tag stig_id: 'UBTU-22-254010'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-78870r1101727_fix'
  tag 'documentable'
  tag cci: ['CCI-004046', 'CCI-004047', 'CCI-000765', 'CCI-000766']
  tag nist: ['IA-2 (6) (a)', 'IA-2 (6) (b)', 'IA-2 (1)', 'IA-2 (2)']

  describe package('sssd') do
    it { should be_installed }
  end

  describe package('libpam-sss') do
    it { should be_installed }
  end

  describe package('libnss-sss') do
    it { should be_installed }
  end
end
