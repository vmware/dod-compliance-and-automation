control 'UBTU-22-612020' do
  title 'Ubuntu 22.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts.'
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
  desc 'check', %q(Verify that the "pam_pkcs11.so" module is configured by using the following command:

     $ grep -i pam_pkcs11.so /etc/pam.d/common-auth
     auth     [success=3 default=ignore]     pam_pkcs11.so

If "pam_pkcs11.so" is commented out or is missing, this is a finding.

Verify the sshd daemon allows public key authentication by using the following command:

     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'pubkeyauthentication'
     /etc/ssh/sshd_config:PubkeyAuthentication yes

If "PubkeyAuthentication" is not set to "yes" or is commented out or missing, or if conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS to use multifactor authentication for access to accounts.

Add or modify the following line in the "/etc/pam.d/common-auth" file:

auth     [success=3 default=ignore]     pam_pkcs11.so

Add or modify the following line in the "/etc/ssh/sshd_config" file:

PubkeyAuthentication yes'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64304r1044768_chk'
  tag severity: 'medium'
  tag gid: 'V-260575'
  tag rid: 'SV-260575r1044770_rule'
  tag stig_id: 'UBTU-22-612020'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-64212r1044769_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-004047', 'CCI-000767', 'CCI-000768']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (6) (b)', 'IA-2 (3)', 'IA-2 (4)']

  describe package('libpam-pkcs11') do
    it { should be_installed }
  end

  describe sshd_config do
    its('PubkeyAuthentication') { should cmp 'yes' }
  end
end
