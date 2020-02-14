control "PHTN-10-000103" do
  title "The Photon operating system must be configured so that all cron paths
are protected from unauthorized modification."
  desc  "If cron files and folders are accessible to unauthorized users then
malicious jobs may be created."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000103"
  tag stig_id: "PHTN-10-000103"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# stat -c \"%n permissions are %a and owned by %U:%G\" /etc/cron.d
/etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly

Expected result:

/etc/cron.d permissions are 755 and owned by root:root
/etc/cron.daily permissions are 755 and owned by root:root
/etc/cron.hourly permissions are 755 and owned by root:root
/etc/cron.monthly permissions are 755 and owned by root:root
/etc/cron.weekly permissions are 755 and owned by root:root

If the output does not match the expected result, this is a finding."
  desc 'fix', "At the command line, execute the following commands for each
returned file:

# chmod 755 <path>
# chown root:root <path>"

  describe file('/etc/cron.d') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      its('mode') { should cmp '0755' }
  end

  describe file('/etc/cron.daily') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      its('mode') { should cmp '0755' }
  end

  describe file('/etc/cron.hourly') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      its('mode') { should cmp '0755' }
  end

  describe file('/etc/cron.daily') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      its('mode') { should cmp '0755' }
  end

  describe file('/etc/cron.weekly') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      its('mode') { should cmp '0755' }
  end

  describe file('/etc/cron.monthly') do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      its('mode') { should cmp '0755' }
  end

end

