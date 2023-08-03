control 'PHTN-30-000097' do
  title 'The Photon operating system must be configured so that all cron paths are protected from unauthorized modification.'
  desc 'If cron files and folders are accessible to unauthorized users, malicious jobs may be created.'
  desc 'check', 'At the command line, run the following command:

# stat -c "%n permissions are %a and owned by %U:%G" /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly

Expected result:

/etc/cron.d permissions are 755 and owned by root:root
/etc/cron.daily permissions are 755 and owned by root:root
/etc/cron.hourly permissions are 755 and owned by root:root
/etc/cron.monthly permissions are 755 and owned by root:root
/etc/cron.weekly permissions are 755 and owned by root:root

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, run the following commands for each returned file:

# chmod 755 <path>
# chown root:root <path>'
  impact 0.5
  tag check_id: 'C-60241r887370_chk'
  tag severity: 'medium'
  tag gid: 'V-256566'
  tag rid: 'SV-256566r887372_rule'
  tag stig_id: 'PHTN-30-000097'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60184r887371_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  crond = directory('/etc/cron.d')
  crondaily = directory('/etc/cron.daily')
  cronhourly = directory('/etc/cron.hourly')
  cronweekly = directory('/etc/cron.weekly')
  cronmonthly = directory('/etc/cron.monthly')

  if !crond.exist? && !crondaily.exist? && !cronhourly.exist? && !cronweekly.exist? && !cronmonthly.exist?
    impact 0.0
    describe 'No cron directories found...skipping.' do
      skip 'No cron directories found...skipping.'
    end
  else
    if crond.exist?
      describe crond do
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
        its('mode') { should cmp '0755' }
      end
    end

    if crondaily.exist?
      describe crondaily do
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
        its('mode') { should cmp '0755' }
      end
    end

    if cronhourly.exist?
      describe cronhourly do
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
        its('mode') { should cmp '0755' }
      end
    end

    if cronweekly.exist?
      describe cronweekly do
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
        its('mode') { should cmp '0755' }
      end
    end

    if cronmonthly.exist?
      describe cronmonthly do
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
        its('mode') { should cmp '0755' }
      end
    end
  end
end
