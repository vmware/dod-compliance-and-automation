control 'UBTU-24-900090' do
  title 'Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the mount command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates audit records upon successful/unsuccessful attempts to use the "mount" command with the following command:

$ sudo auditctl -l | grep /usr/bin/mount
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-mount

If the command does not return lines that match the example or the lines are commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "mount" command.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-mount

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74813r1066827_chk'
  tag severity: 'medium'
  tag gid: 'V-270780'
  tag rid: 'SV-270780r1066829_rule'
  tag stig_id: 'UBTU-24-900090'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-74714r1066828_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  @audit_file = '/usr/bin/mount'

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
