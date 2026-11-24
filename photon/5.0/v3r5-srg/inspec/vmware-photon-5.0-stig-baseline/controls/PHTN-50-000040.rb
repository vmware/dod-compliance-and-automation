control 'PHTN-50-000040' do
  title 'The Photon operating system must not have the telnet package installed.'
  desc  'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify telnet is not installed:

    # rpm -qa | grep telnet

    If any results are returned indicating telnet is installed, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following command:

    # tdnf remove <package name>
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag gid: 'V-PHTN-50-000040'
  tag rid: 'SV-PHTN-50-000040'
  tag stig_id: 'PHTN-50-000040'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  describe command('rpm -qa | grep telnet') do
    its('stdout') { should cmp '' }
    its('stderr') { should cmp '' }
  end
end
