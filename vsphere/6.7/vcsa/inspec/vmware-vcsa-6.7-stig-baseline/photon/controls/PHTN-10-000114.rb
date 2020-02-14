control "PHTN-10-000114" do
  title "The Photon OS must not have the xinetd service enabled."
  desc  "The xinetd service is not required for normal appliance operation and
must be disabled."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000114"
  tag stig_id: "PHTN-10-000114"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# systemctl is-enabled xinetd.service

Expected result:

disabled

If the output does not match the expected result, this is a finding"
  desc 'fix', "At the command line, execute the following commands:

# service xinetd stop
# systemctl disable xinetd.service"

  describe systemd_service('xinetd.service') do
    it { should_not be_enabled}
    it { should_not be_running}
  end

end

