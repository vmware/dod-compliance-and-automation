control 'PHTN-67-000051' do
  title "The Photon operating system must protect audit tools from unauthorized
modification."
  desc  "Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operations on audit information.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # stat -c \"%n permissions are %a\" /usr/sbin/auditctl /usr/sbin/auditd
/usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace

    If any file is more permissive than 750, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command for each file returned:

    # chmod 750 <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag satisfies: ['SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag gid: 'V-239122'
  tag rid: 'SV-239122r675174_rule'
  tag stig_id: 'PHTN-67-000051'
  tag fix_id: 'F-42292r675173_fix'
  tag cci: ['CCI-001494', 'CCI-001495']
  tag nist: ['AU-9', 'AU-9']

  describe file('/usr/sbin/auditctl') do
    it { should_not be_more_permissive_than('0750') }
  end

  describe file('/usr/sbin/auditd') do
    it { should_not be_more_permissive_than('0750') }
  end

  describe file('/usr/sbin/aureport') do
    it { should_not be_more_permissive_than('0750') }
  end

  describe file('/usr/sbin/ausearch') do
    it { should_not be_more_permissive_than('0750') }
  end

  describe file('/usr/sbin/autrace') do
    it { should_not be_more_permissive_than('0750') }
  end
end
