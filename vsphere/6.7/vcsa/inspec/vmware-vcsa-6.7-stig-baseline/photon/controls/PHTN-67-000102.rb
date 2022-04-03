control 'PHTN-67-000102' do
  title "The Photon operating system must be configured so that all cron jobs
are protected from unauthorized modification."
  desc  "If cron files and folders are accessible to unauthorized users,
malicious jobs may be created."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # find /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.monthly/
/etc/cron.weekly/ -xdev -type f -a '(' -perm -002 -o -not -user root -o -not
-group root ')' -exec ls -ld {} \\;

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
  tag gid: 'V-239173'
  tag rid: 'SV-239173r675327_rule'
  tag stig_id: 'PHTN-67-000102'
  tag fix_id: 'F-42343r675326_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("find /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.monthly/ /etc/cron.weekly/ -xdev -type f -a '(' -perm -002 -o -not -user root -o -not -group root ')' -exec ls -ld {} \;") do
    its('stdout') { should eq '' }
  end
end
