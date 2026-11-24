control 'UBTU-24-200320' do
  title 'Ubuntu 24.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.

'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/security/opasswd" with the following command:

$ sudo auditctl -l | grep opasswd
-w /etc/security/opasswd -p wa -k usergroup_modification

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/security/opasswd".

Add or update the following rule to "/etc/audit/rules.d/stig.rules":

-w /etc/security/opasswd -p wa -k usergroup_modification

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74721r1066551_chk'
  tag severity: 'medium'
  tag gid: 'V-270688'
  tag rid: 'SV-270688r1066553_rule'
  tag stig_id: 'UBTU-24-200320'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-74622r1066552_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000476-GPOS-00221']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130', 'CCI-000172']
  tag nist: ['AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AU-12 c']

  @audit_file = '/etc/security/opasswd'
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
