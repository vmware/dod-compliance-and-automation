control 'UBTU-22-654050' do
  title 'Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the gpasswd command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify that an audit event is generated for any successful/unsuccessful use of the "gpasswd" command by using the following command:

     $ sudo auditctl -l | grep -w gpasswd
     -a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-gpasswd

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The "key=" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "gpasswd" command.

Add or modify the following line in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-gpasswd

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64341r953647_chk'
  tag severity: 'medium'
  tag gid: 'V-260612'
  tag rid: 'SV-260612r958446_rule'
  tag stig_id: 'UBTU-22-654050'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-64249r953648_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  @audit_file = '/usr/bin/gpasswd'

  audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
    end

    @perms = auditd.file(@audit_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include 'x' }
      end
    end
  else
    describe("Audit line(s) for #{@audit_file} exist") do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end
