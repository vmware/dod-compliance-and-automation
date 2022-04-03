control 'PHTN-67-000018' do
  title 'The Photon operating system must have the auditd service running.'
  desc  "Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one. To that end, the auditd service
must be configured to start automatically and be running at all times.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # service auditd status | grep running

    If the service is not running, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command:

    # systemctl enable auditd.service
    # service auditd start
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000042-GPOS-00021',
'SRG-OS-000255-GPOS-00096', 'SRG-OS-000363-GPOS-00150',
'SRG-OS-000365-GPOS-00152', 'SRG-OS-000445-GPOS-00199',
'SRG-OS-000446-GPOS-00200', 'SRG-OS-000461-GPOS-00205',
'SRG-OS-000465-GPOS-00209', 'SRG-OS-000467-GPOS-00211',
'SRG-OS-000474-GPOS-00219', 'SRG-OS-000475-GPOS-00220']
  tag gid: 'V-239090'
  tag rid: 'SV-239090r675078_rule'
  tag stig_id: 'PHTN-67-000018'
  tag fix_id: 'F-42260r675077_fix'
  tag cci: ['CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-001487',
'CCI-001744', 'CCI-001814', 'CCI-002696', 'CCI-002699']
  tag nist: ['AU-3 (1)', 'AU-12 a', 'AU-12 c', 'AU-3', 'CM-3 (5)', 'CM-5 (1)',
'SI-6 a', 'SI-6 b']

  describe systemd_service('auditd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end
