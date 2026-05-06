control 'UBTU-24-100010' do
  title 'Ubuntu 24.04 LTS must not have the "systemd-timesyncd" package installed.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'Verify the "systemd-timesyncd" package is not installed with the following command:

$ dpkg -l | grep systemd-timesyncd

If the "systemd-timesyncd" package is installed, this is a finding.'
  desc 'fix', 'The "systemd-timesyncd" package will be uninstalled as part of the "chrony" package install. Purge the remaining configuration files for "systemd-timesyncd" from Ubuntu 24.04 LTS:

$ sudo apt-get purge systemd-timesyncd'
  impact 0.3
  tag check_id: 'C-74678r1066422_chk'
  tag severity: 'low'
  tag gid: 'V-270645'
  tag rid: 'SV-270645r1068357_rule'
  tag stig_id: 'UBTU-24-100010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-74579r1066423_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe package('systemd-timesyncd') do
    it { should_not be_installed }
  end

  describe command('dpkg -l | grep systemd-timesyncd') do
    its('stdout') { should_not match(/rc/) }
  end
end
