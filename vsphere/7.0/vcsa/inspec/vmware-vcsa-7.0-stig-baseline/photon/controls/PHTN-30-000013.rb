control 'PHTN-30-000013' do
  title 'The Photon operating system must have the auditd service running.'
  desc  'Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). They also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # systemctl status auditd

    If the service is not running, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands:

    # systemctl enable auditd
    # systemctl start auditd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000042-GPOS-00021'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000363-GPOS-00150', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000445-GPOS-00199', 'SRG-OS-000446-GPOS-00200', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000465-GPOS-00209', 'SRG-OS-000467-GPOS-00211', 'SRG-OS-000474-GPOS-00219', 'SRG-OS-000475-GPOS-00220']
  tag gid: 'V-256490'
  tag rid: 'SV-256490r887144_rule'
  tag stig_id: 'PHTN-30-000013'
  tag cci: ['CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-001487', 'CCI-001744', 'CCI-001814', 'CCI-002696', 'CCI-002699']
  tag nist: ['AU-12 a', 'AU-12 c', 'AU-3', 'AU-3 (1)', 'CM-3 (5)', 'CM-5 (1)', 'SI-6 a', 'SI-6 b']

  describe systemd_service('auditd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end
