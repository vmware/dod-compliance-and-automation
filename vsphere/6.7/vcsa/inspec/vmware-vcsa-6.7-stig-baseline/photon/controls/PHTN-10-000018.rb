control "PHTN-10-000018" do
  title "The Photon operating system must have the auditd service running."
  desc  "Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one. To that end, the auditd service
must be configured to start automatically and be running at all times."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000062-GPOS-00031"
  tag gid: nil
  tag rid: "PHTN-10-000018"
  tag stig_id: "PHTN-10-000018"
  tag cci: "CCI-000169"
  tag nist: ["AU-12 a", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# service auditd status | grep running

If the service is not running this is a finding."
  desc 'fix', "At the command line, execute the following command:

# systemctl enable auditd.service
# service auditd start"

  describe systemd_service('auditd') do
    it { should be_installed}
    it { should be_enabled}
    it { should be_running}
  end

end

