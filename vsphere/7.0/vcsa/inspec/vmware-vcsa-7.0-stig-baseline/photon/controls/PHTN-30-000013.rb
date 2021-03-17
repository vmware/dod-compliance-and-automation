# encoding: UTF-8

control 'PHTN-30-000013' do
  title 'The Photon operating system must have the auditd service running.'
  desc  "Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one. To that end, the auditd service
must be configured to start automatically and be running at all times."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # systemctl status auditd

    If the service is not running this is a finding.
  "
  desc  'fix', "
    At the command line, execute the following command:

    # systemctl enable auditd
    # systemctl start auditd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000042-GPOS-00021'
  tag stig_id: 'PHTN-30-000013'
  tag cci: 'CCI-000135'
  tag nist: ['AU-3 (1)']

  describe systemd_service('auditd') do
    it { should be_installed}
    it { should be_enabled}
    it { should be_running}
  end

end

