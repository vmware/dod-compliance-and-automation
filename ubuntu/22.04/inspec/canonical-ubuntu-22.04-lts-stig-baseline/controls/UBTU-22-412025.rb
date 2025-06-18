control 'UBTU-22-412025' do
  title 'Ubuntu 22.04 LTS must allow users to directly initiate a session lock for all connection types.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, Ubuntu 22.04 LTS need to provide users with the ability to manually invoke a session lock so users may secure their session if they need to temporarily vacate the immediate physical vicinity.

'
  desc 'check', 'Verify Ubuntu 22.04 LTS has the "vlock" package installed by using the following command:

     $ dpkg -l | grep vlock
     ii     vlock     2.2.2-10     amd64     Virtual Console locking program

If "vlock" is not installed, this is a finding.'
  desc 'fix', 'Install the "vlock" package by using the following command:

     $ sudo apt-get install vlock'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64282r953470_chk'
  tag severity: 'medium'
  tag gid: 'V-260553'
  tag rid: 'SV-260553r1015010_rule'
  tag stig_id: 'UBTU-22-412025'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-64190r953471_fix'
  tag satisfies: ['SRG-OS-000030-GPOS-00011', 'SRG-OS-000031-GPOS-00012']
  tag 'documentable'
  tag cci: ['CCI-000058', 'CCI-000060', 'CCI-000057']
  tag nist: ['AC-11 a', 'AC-11 (1)']

  describe package('vlock') do
    it { should be_installed }
  end
end
