control 'PHTN-30-000111' do
  title 'The Photon operating system must protect all boot configuration files from unauthorized modification.'
  desc  'Boot configuration files control how the system boots, including single-user mode, auditing, log levels, etc. Improper or malicious configurations can negatively affect system security and availability.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # find /boot/*.cfg -xdev -type f -a '(' -perm -002 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands for each returned file:

    # chmod 644 <file>
    # chown root:root <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-30-000111'
  tag rid: 'SV-PHTN-30-000111'
  tag stig_id: 'PHTN-30-000111'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("find /boot/*.cfg -xdev -type f -a '(' -perm -002 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;") do
    its('stdout') { should eq '' }
  end
end
