control 'PHTN-67-000100' do
  title "The Photon operating system must be configured so that all files have
a valid owner and group owner."
  desc  "If files do not have valid user and group owners, unintended access to
files could occur."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # find / -fstype ext4 -nouser -o -nogroup -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command for each returned file:

    # chown root:root <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239171'
  tag rid: 'SV-239171r675321_rule'
  tag stig_id: 'PHTN-67-000100'
  tag fix_id: 'F-42341r675320_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('find / -fstype ext4 -nouser -o -nogroup -exec ls -ld {} \;') do
    its('stdout') { should eq '' }
  end
end
