control 'UBTU-24-100700' do
  title 'Ubuntu 24.04 LTS must have the "chrony" package installed.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'Verify the "chrony" package is installed using the following command:

$ dpkg -l | grep chrony
ii  chrony     4.5-1ubuntu4.1     amd64     Versatile implementation of the Network Time Protocol

If the "chrony" package is not installed, this is a finding.'
  desc 'fix', 'Install the "chrony" network time protocol package using the following command:

$ sudo apt install -y chrony'
  impact 0.3
  tag check_id: 'C-74697r1067157_chk'
  tag severity: 'low'
  tag gid: 'V-270664'
  tag rid: 'SV-270664r1068359_rule'
  tag stig_id: 'UBTU-24-100700'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-74598r1067158_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe package('chrony') do
    it { should be_installed }
  end
end
