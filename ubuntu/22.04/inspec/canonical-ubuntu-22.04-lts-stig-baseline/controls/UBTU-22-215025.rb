control 'UBTU-22-215025' do
  title 'Ubuntu 22.04 LTS must not have the "ntp" package installed.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'Verify that the "ntp" package is not installed by using the following command:

     $ dpkg -l | grep ntp

If the "ntp" package is installed, this is a finding.'
  desc 'fix', 'Uninstall the "ntp" package by using the following command:

     $ sudo dpkg -P --force-all ntp'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64210r953254_chk'
  tag severity: 'low'
  tag gid: 'V-260481'
  tag rid: 'SV-260481r991589_rule'
  tag stig_id: 'UBTU-22-215025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-64118r953255_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe package('ntp') do
    it { should_not be_installed }
  end

  describe command('dpkg -l | grep ntp') do
    its('stdout') { should_not match /rc/ }
  end
end
