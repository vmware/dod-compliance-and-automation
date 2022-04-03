control 'PHTN-67-000118' do
  title "The Photon operating system must protect all boot configuration files
from unauthorized access."
  desc  "Boot configuration files control how the system boots, including
single-user mode, auditing, log levels, etc. Improper or malicious
configurations can negatively affect system security and availability."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # find /boot/*.cfg -xdev -type f -a '(' -not -perm 600 -o -not -user root
-o -not -group root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following commands for each returned file:

    # chmod 600 <file>
    # chown root:root <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239189'
  tag rid: 'SV-239189r675375_rule'
  tag stig_id: 'PHTN-67-000118'
  tag fix_id: 'F-42359r675374_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("find /boot/*.cfg -xdev -type f -a '(' -not -perm 600 -o -not -user root -o -not -group root ')' -exec ls -ld {} \;") do
    its('stdout') { should eq '' }
  end
end
