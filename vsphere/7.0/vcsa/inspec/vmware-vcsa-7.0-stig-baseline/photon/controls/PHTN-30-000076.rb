control 'PHTN-30-000076' do
  title 'The Photon operating system must disable the debug-shell service.'
  desc 'The debug-shell service is intended to diagnose systemd-related boot issues with various "systemctl" commands. Once enabled and following a system reboot, the root shell will be available on tty9. This service must remain disabled until and unless otherwise directed by VMware support.'
  desc 'check', 'At the command line, run the following command:

# systemctl status debug-shell.service|grep -E --color=always disabled

If the debug-shell service is not disabled, this is a finding.'
  desc 'fix', 'At the command line, run the following commands:

# systemctl stop debug-shell.service
# systemctl disable debug-shell.service

Reboot for changes to take effect.'
  impact 0.5
  tag check_id: 'C-60221r887310_chk'
  tag severity: 'medium'
  tag gid: 'V-256546'
  tag rid: 'SV-256546r887312_rule'
  tag stig_id: 'PHTN-30-000076'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60164r887311_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe systemd_service('debug-shell.service') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
