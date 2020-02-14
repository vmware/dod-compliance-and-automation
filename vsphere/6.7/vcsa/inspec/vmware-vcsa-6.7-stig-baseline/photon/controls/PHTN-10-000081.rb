control "PHTN-10-000081" do
  title "The Photon operating system must disabled the debug-shell service."
  desc  "The debug-shell service is intended to diagnose systemd related boot
issues with various systemctl commands. Once enabled and following a system
reboot, the root shell will be available on tty9. This service must remain
disabled until and unless otherwise directed by VMware support."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000081"
  tag stig_id: "PHTN-10-000081"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# systemctl status debug-shell.service|grep -E --color=always disabled

If the debug-shell service is not disabled, this is a finding."
  desc 'fix', "At the command line, execute the following commands:

# systemctl stop debug-shell.service
# systemctl disable debug-shell.service

Reboot for changes to take effect."

  describe systemd_service('debug-shell.service') do
    it { should_not be_enabled}
    it { should_not be_running}
  end

end

