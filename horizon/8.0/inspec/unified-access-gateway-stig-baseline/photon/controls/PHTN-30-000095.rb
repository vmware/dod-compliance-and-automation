control 'PHTN-30-000095' do
  title 'The Photon operating system must be configured so that the /etc/cron.allow file is protected from unauthorized modification.'
  desc  'If cron files and folders are accessible to unauthorized users, malicious jobs may be created.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # stat -c \"%n permissions are %a and owned by %U:%G\" /etc/cron.allow

    Expected result:

    /etc/cron.allow permissions are 600 and owned by root:root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command(s):

    # chmod 600 /etc/cron.allow
    # chown root:root /etc/cron.allow
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000095'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/cron.allow') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    its('mode') { should cmp '0600' }
  end
end
