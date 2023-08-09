control 'PHTN-30-000095' do
  title 'The Photon operating system must be configured so the "/etc/cron.allow" file is protected from unauthorized modification.'
  desc 'If cron files and folders are accessible to unauthorized users, malicious jobs may be created.'
  desc 'check', 'At the command line, run the following command:

# stat -c "%n permissions are %a and owned by %U:%G" /etc/cron.allow

Expected result:

/etc/cron.allow permissions are 600 and owned by root:root

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, run the following commands:

# chmod 600 /etc/cron.allow
# chown root:root /etc/cron.allow'
  impact 0.5
  tag check_id: 'C-60239r887364_chk'
  tag severity: 'medium'
  tag gid: 'V-256564'
  tag rid: 'SV-256564r887366_rule'
  tag stig_id: 'PHTN-30-000095'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60182r887365_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/cron.allow') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    its('mode') { should cmp '0600' }
  end
end
