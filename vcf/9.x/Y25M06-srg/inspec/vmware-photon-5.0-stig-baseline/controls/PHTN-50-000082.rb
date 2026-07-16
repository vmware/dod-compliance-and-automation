control 'PHTN-50-000082' do
  title 'The Photon operating system must protect audit tools from unauthorized access.'
  desc  "
    Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

    Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

    Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify permissions on audit tools:

    # stat -c \"%n is owned by %U and group owned by %G and permissions are %a\" /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace /usr/sbin/augenrules

    Expected result:

    /usr/sbin/auditctl is owned by root and group owned by root and permissions are 755
    /usr/sbin/auditd is owned by root and group owned by root and permissions are 755
    /usr/sbin/aureport is owned by root and group owned by root and permissions are 755
    /usr/sbin/ausearch is owned by root and group owned by root and permissions are 755
    /usr/sbin/autrace is owned by root and group owned by root and permissions are 755
    /usr/sbin/augenrules is owned by root and group owned by root and permissions are 750

    If any file is not owned by root or group owned by root or permissions are more permissive than listed above, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands for each file returned:

    # chown root:root <file>
    # chmod 750 <file>

    Note: Update permissions to match the target file as listed in the check text.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag satisfies: ['SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag gid: 'V-PHTN-50-000082'
  tag rid: 'SV-PHTN-50-000082'
  tag stig_id: 'PHTN-50-000082'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9', 'AU-9 a']

  describe file('/usr/sbin/auditctl') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0755') }
  end
  describe file('/usr/sbin/auditd') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0755') }
  end
  describe file('/usr/sbin/aureport') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0755') }
  end
  describe file('/usr/sbin/ausearch') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0755') }
  end
  describe file('/usr/sbin/autrace') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0755') }
  end
  describe file('/usr/sbin/augenrules') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0750') }
  end
end
