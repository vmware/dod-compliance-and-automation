control 'UBTU-24-900250' do
  title 'Ubuntu 24.04 LTS must generate audit records for the use and modification of faillog file.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates an audit record upon successful/unsuccessful modifications to the "faillog" file with the following command:

$ sudo auditctl -l | grep faillog
-w /var/log/faillog -p wa -k logins

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful modifications to the "faillog" file.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-w /var/log/faillog -p wa -k logins

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74829r1066875_chk'
  tag severity: 'medium'
  tag gid: 'V-270796'
  tag rid: 'SV-270796r1066877_rule'
  tag stig_id: 'UBTU-24-900250'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-74730r1066876_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  @audit_file = '/var/log/faillog'

  audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
    end

    @perms = auditd.file(@audit_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include 'w' }
        it { should include 'a' }
      end
    end
  else
    describe("Audit line(s) for #{@audit_file} exist") do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end
