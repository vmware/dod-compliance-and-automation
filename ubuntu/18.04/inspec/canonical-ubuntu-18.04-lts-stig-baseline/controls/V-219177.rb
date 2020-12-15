# encoding: UTF-8

control 'V-219177' do
  title "The Ubuntu operating system must not have the telnet package
installed."
  desc  "Passwords need to be protected at all times, and encryption is the
standard method for protecting passwords. If passwords are not encrypted, they
can be plainly read (i.e., clear text) and easily compromised."
  desc  'rationale', ''
  desc  'check', "
    Verify that the telnet package is not installed on the Ubuntu operating
system.

    Check that the telnet daemon is not installed on the Ubuntu operating
system by running the following command:

    # dpkg -l | grep telnetd

    If the package is installed, this is a finding.
  "
  desc  'fix', "
    Remove the telnet package from the Ubuntu operating system by running the
following command:

    # sudo apt-get remove telnetd
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag gid: 'V-219177'
  tag rid: 'SV-219177r508662_rule'
  tag stig_id: 'UBTU-18-010105'
  tag fix_id: 'F-20901r304860_fix'
  tag cci: ['V-100581', 'SV-109685', 'CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  describe package('telnetd') do
    it { should_not be_installed }
  end
end

