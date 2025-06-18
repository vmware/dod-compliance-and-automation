control 'UBTU-22-654225' do
  title 'Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 22.04 LTS generates audit records for all modifications that affect "/etc/sudoers.d" directory by using the following command:

     $ sudo auditctl -l | grep sudoers.d
     -w /etc/sudoers.d -p wa -k privilege_modification

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The "-k" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to generate audit records for all modifications that affect "/etc/sudoers.d" directory.

Add or modify the following line to "/etc/audit/rules.d/stig.rules":

-w /etc/sudoers.d -p wa -k privilege_modification

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation.  he <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64376r953752_chk'
  tag severity: 'medium'
  tag gid: 'V-260647'
  tag rid: 'SV-260647r991575_rule'
  tag stig_id: 'UBTU-22-654225'
  tag gtitle: 'SRG-OS-000466-GPOS-00210'
  tag fix_id: 'F-64284r953753_fix'
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
