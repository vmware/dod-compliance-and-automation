control 'UBTU-24-100020' do
  title 'Ubuntu 24.04 LTS must not have the "ntp" package installed.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'Verify the "ntp" package is not installed with the following command:

$ dpkg -l | grep ntp

If the "ntp" package is installed, this is a finding.'
  desc 'fix', 'Uninstall the "ntp" package using the following command:

$ sudo apt remove ntp

If there are additional configuration files on the system that must be removed, the following command can be used instead:

$ sudo apt-get purge ntp'
  impact 0.3
  tag check_id: 'C-74679r1066425_chk'
  tag severity: 'low'
  tag gid: 'V-270646'
  tag rid: 'SV-270646r1068358_rule'
  tag stig_id: 'UBTU-24-100020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-74580r1066426_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe package('ntp') do
    it { should_not be_installed }
  end

  describe command('dpkg -l | grep ntp') do
    its('stdout') { should_not match(/rc/) }
  end
end
