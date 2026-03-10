control 'PHTN-40-000016' do
  title 'The Photon operating system must enable the auditd service.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. To that end, the auditd service must be configured to start automatically and be running at all times.'
  desc 'check', 'At the command line, run the following command to verify auditd is enabled and running:

# systemctl status auditd

If the service is not enabled and running, this is a finding.'
  desc 'fix', 'At the command line, run the following commands:

# systemctl enable auditd
# systemctl start auditd'
  impact 0.5
  tag check_id: 'C-62548r933483_chk'
  tag severity: 'medium'
  tag gid: 'V-258808'
  tag rid: 'SV-258808r1003628_rule'
  tag stig_id: 'PHTN-40-000016'
  tag gtitle: 'SRG-OS-000039-GPOS-00017'
  tag fix_id: 'F-62457r933484_fix'
  tag satisfies: ['SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000363-GPOS-00150', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000446-GPOS-00200']
  tag cci: ['CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000169', 'CCI-001487', 'CCI-001744', 'CCI-003938', 'CCI-002699']
  tag nist: ['AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-12 a', 'AU-3 f', 'CM-3 (5)', 'CM-5 (1) (b)', 'SI-6 b']

  describe systemd_service('auditd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end
