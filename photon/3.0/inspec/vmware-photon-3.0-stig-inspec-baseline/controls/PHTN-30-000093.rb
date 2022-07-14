control 'PHTN-30-000093' do
  title 'The Photon operating system must be configured so that all system startup scripts are protected from unauthorized modification.'
  desc  'If system startup scripts are accessible to unauthorized modification, this could compromise the system on startup.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # find /etc/rc.d/* -xdev -type f -a '(' -perm -002 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following commands for each returned file:

    # chmod o-w <file>
    # chown root:root <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000093'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("find /etc/rc.d/* -xdev -type f -a '(' -perm -002 -o -not -user root -o -not -group root ')' -exec ls -ld {} \;") do
    its('stdout') { should eq '' }
  end
end
