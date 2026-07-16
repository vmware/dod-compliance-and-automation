control 'UBTU-24-400020' do
  title 'Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include:
1) Something a user knows (e.g., password/PIN);
2) Something a user has (e.g., cryptographic identification device, token); and
3) Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

The DOD common access card (CAC) with DOD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'Verify that the "pam_pkcs11.so" module is configured with the following command:

$ grep -r pam_pkcs11.so /etc/pam.d/common-auth
auth    [success=2 default=ignore] pam_pkcs11.so

If the module is not configured, is missing, or commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to use multifactor authentication for access to accounts.

Add or update "pam_pkcs11.so" in "/etc/pam.d/common-auth" to match the following line:

auth    [success=2 default=ignore] pam_pkcs11.so'
  impact 0.5
  tag check_id: 'C-74754r1066650_chk'
  tag severity: 'medium'
  tag gid: 'V-270721'
  tag rid: 'SV-270721r1066652_rule'
  tag stig_id: 'UBTU-24-400020'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-74655r1066651_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766']
  tag nist: ['IA-2 (1)', 'IA-2 (2)']

  common_auth_file = input('common_auth_file')

  libpam_pkcs11_package = package('libpam-pkcs11')

  if libpam_pkcs11_package.installed?
    describe file(common_auth_file) do
      it { should exist }
    end
    describe command("grep pam_pkcs11.so #{common_auth_file}") do
      its('exit_status') { should eq 0 }
      its('stdout.strip') { should match(/^\s*auth\s+\[success=2\s+default=ignore\]\s+pam_pkcs11\.so\b/) }
    end
  else
    describe libpam_pkcs11_package do
      it { should be_installed }
    end
  end
end
