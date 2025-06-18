control 'UBTU-22-215015' do
  title 'Ubuntu 22.04 LTS must have the "chrony" package installed.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'Verify the "chrony" package is installed using the following command:

     $ dpkg -l | grep chrony
     ii     chrony     4.2-2ubuntu2     amd64     Versatile implementation of the Network Time Protocol

If the "chrony" package is not installed, this is a finding.'
  desc 'fix', 'Install the "chrony" network time protocol package using the following command:

     $ sudo apt-get install chrony'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64208r953248_chk'
  tag severity: 'low'
  tag gid: 'V-260479'
  tag rid: 'SV-260479r991589_rule'
  tag stig_id: 'UBTU-22-215015'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-64116r953249_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe package('chrony') do
    it { should be_installed }
  end
end
