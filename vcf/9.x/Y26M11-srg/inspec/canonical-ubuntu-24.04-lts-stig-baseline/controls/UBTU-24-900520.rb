control 'UBTU-24-900520' do
  title 'Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates audit records for all modifications that affect "/etc/sudoers.d" directory with the following command:

$ sudo auditctl -l | grep sudoers.d
-w /etc/sudoers.d -p wa -k privilege_modification

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to generate audit records for all modifications that affect "/etc/sudoers.d" directory.

Add or update the following rule to "/etc/audit/rules.d/stig.rules":

-w /etc/sudoers.d -p wa -k privilege_modification

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74841r1066911_chk'
  tag severity: 'medium'
  tag gid: 'V-270808'
  tag rid: 'SV-270808r1067100_rule'
  tag stig_id: 'UBTU-24-900520'
  tag gtitle: 'SRG-OS-000466-GPOS-00210'
  tag fix_id: 'F-74742r1066912_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  @audit_file = '/etc/sudoers.d'

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
