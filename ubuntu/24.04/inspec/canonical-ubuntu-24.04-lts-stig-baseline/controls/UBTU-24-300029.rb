control 'UBTU-24-300029' do
  title 'Ubuntu 24.04 LTS must generate audit records for all events that affect the systemd journal files.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to modify system level binaries and their operation. Auditing the systemd journal files provides logging that can be used for forensic purposes.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates audit records for all events that affect "/var/log/journal" with the following command:

$ sudo auditctl -l | grep journal
-w /var/log/journal -p wa -k systemd_journal

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to generate audit records for events that affect "/var/log/journal".

Add or update the following rule to "/etc/audit/rules.d/stig.rules":

-w /var/log/journal -p wa -k systemd_journal

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74748r1066632_chk'
  tag severity: 'medium'
  tag gid: 'V-270715'
  tag rid: 'SV-270715r1066634_rule'
  tag stig_id: 'UBTU-24-300029'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-74649r1066633_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  @audit_file = '/var/log/journal'

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
