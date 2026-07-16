control 'UBTU-24-100660' do
  title 'Ubuntu 24.04 LTS must use the "SSSD" package for multifactor authentication services.'
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
  desc 'check', 'Verify the "sssd.service" is enabled and active with the following commands:

$ sudo systemctl is-enabled sssd
enabled

$ sudo systemctl is-active sssd
active

If "sssd.service" is not active or enabled, this is a finding.'
  desc 'fix', 'Enable the "sssd.service to start automatically on reboot with the following command:

$ sudo systemctl enable sssd.service

ensure the "sssd" service is running

$ sudo systemctl start sssd.service'
  impact 0.5
  tag check_id: 'C-74696r1066476_chk'
  tag severity: 'medium'
  tag gid: 'V-270663'
  tag rid: 'SV-270663r1066478_rule'
  tag stig_id: 'UBTU-24-100660'
  tag gtitle: 'SRG-OS-000705-GPOS-00150'
  tag fix_id: 'F-74597r1066477_fix'
  tag satisfies: ['SRG-OS-000705-GPOS-00150', 'SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000375-GPOS-00160']
  tag 'documentable'
  tag cci: ['CCI-004046', 'CCI-004047', 'CCI-000765', 'CCI-000766']
  tag nist: ['IA-2 (6) (a)', 'IA-2 (6) (b)', 'IA-2 (1)', 'IA-2 (2)']

  describe systemd_service('sssd') do
    it { should be_enabled }
    it { should be_running }
  end
end
