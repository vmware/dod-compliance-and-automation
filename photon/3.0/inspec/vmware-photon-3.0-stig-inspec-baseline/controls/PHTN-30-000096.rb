control 'PHTN-30-000096' do
  title 'The Photon operating system must be configured so that all cron jobs are protected from unauthorized modification.'
  desc  'If cron files and folders are accessible to unauthorized users, malicious jobs may be created.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # find /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.monthly/ /etc/cron.weekly/ -xdev -type f -a '(' -perm -022 -o -not -user root ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands for each returned file:

    # chmod 644 <file>
    # chown root <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-30-000096'
  tag rid: 'SV-PHTN-30-000096'
  tag stig_id: 'PHTN-30-000096'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("find /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.monthly/ /etc/cron.weekly/ -xdev -type f -a '(' -perm -022 -o -not -user root ')' -exec ls -ld {} \\;") do
    its('stdout') { should cmp '' }
  end
end
