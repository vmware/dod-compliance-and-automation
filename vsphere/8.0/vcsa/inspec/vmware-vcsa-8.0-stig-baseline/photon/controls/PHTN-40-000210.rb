control 'PHTN-40-000210' do
  title 'The Photon operating system must disable the debug-shell service.'
  desc 'The debug-shell service is intended to diagnose systemd related boot issues with various systemctl commands. Once enabled and following a system reboot, the root shell will be available on tty9. This service must remain disabled until and unless otherwise directed by VMware support.'
  desc 'check', 'At the command line, run the following command to verify the debug-shell service is disabled:

# systemctl status debug-shell.service

If the debug-shell service is not stopped and disabled, this is a finding.'
  desc 'fix', 'At the command line, run the following commands:

# systemctl stop debug-shell.service
# systemctl disable debug-shell.service'
  impact 0.5
  tag check_id: 'C-62613r933678_chk'
  tag severity: 'medium'
  tag gid: 'V-258873'
  tag rid: 'SV-258873r933680_rule'
  tag stig_id: 'PHTN-40-000210'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62522r933679_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe systemd_service('debug-shell.service') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
