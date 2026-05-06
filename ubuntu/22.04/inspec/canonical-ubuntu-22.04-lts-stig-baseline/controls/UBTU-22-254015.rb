control 'UBTU-22-254015' do
  title 'Ubuntu 22.04 LTS must use the "SSSD" package for multifactor authentication services.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include:
1) Something a user knows (e.g., password/PIN);
2) Something a user has (e.g., cryptographic identification device, token); and
3) Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

The DOD common access card (CAC) with DOD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify the "sssd.service" is enabled and active with the following commands:

$ sudo systemctl is-enabled sssd
enabled

$ sudo systemctl is-active sssd
active

If "sssd.service" is not active or enabled, this is a finding.'
  desc 'fix', 'Enable the "sssd.service to start automatically on reboot with the following command:

$ sudo systemctl enable sssd.service

Ensure the "sssd" service is running:

$ sudo systemctl start sssd.service'
  impact 0.5
  tag check_id: 'C-78967r1101737_chk'
  tag severity: 'medium'
  tag gid: 'V-274866'
  tag rid: 'SV-274866r1101739_rule'
  tag stig_id: 'UBTU-22-254015'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-78872r1101738_fix'
  tag 'documentable'
  tag cci: ['CCI-004046', 'CCI-004047', 'CCI-000765', 'CCI-000766']
  tag nist: ['IA-2 (6) (a)', 'IA-2 (6) (b)', 'IA-2 (1)', 'IA-2 (2)']

  describe systemd_service('sssd') do
    it { should be_enabled }
    it { should be_running }
  end
end
