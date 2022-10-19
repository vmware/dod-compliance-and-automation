control 'PHTN-30-000048' do
  title 'The Photon operating system must protect audit tools from unauthorized modification and deletion.'
  desc  'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operations on audit information.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # stat -c \"%n is owned by %U and group owned by %G and permissions are %a\" /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace

    If any file is not owned by root or group owned by root or permissions are more permissive than 750, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command for each file returned for user and group ownership:

    # chown root:root <file>

    At the command line, execute the following command for each file returned for file permissions:

    # chmod 750 <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag satisfies: []
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000048'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']

  describe file('/usr/sbin/auditctl') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0750') }
  end

  describe file('/usr/sbin/auditd') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0750') }
  end

  describe file('/usr/sbin/aureport') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0750') }
  end

  describe file('/usr/sbin/ausearch') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0750') }
  end

  describe file('/usr/sbin/autrace') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0750') }
  end
end
