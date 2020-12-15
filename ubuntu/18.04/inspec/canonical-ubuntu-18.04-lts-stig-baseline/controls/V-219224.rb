# encoding: UTF-8

control 'V-219224' do
  title "The Ubuntu operating system must generate audit records for all
account creations, modifications, disabling, and termination events that affect
/etc/security/opasswd."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system generates audit records for all account
creations, modifications, disabling, and termination events that affect
/etc/security/opasswd.

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep opasswd

    -w /etc/security/opasswd -p wa -k usergroup_modification

    If the command does not return a line that matches the example or the line
is commented out, this is a finding.

    Note: The '-k' allows for specifying an arbitrary identifier and the string
after it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to generate audit records for all
account creations, modifications, disabling, and termination events that affect
/etc/security/opasswd.

    Add or update the following rule to \"/etc/audit/rules.d/stig.rules\":

    -w /etc/security/opasswd -p wa -k usergroup_modification

    Note:
    The \"root\" account must be used to view/edit any files in the
/etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000476-GPOS-00221'
  tag satisfies: ['SRG-OS-000476-GPOS-00221', 'SRG-OS-000463-GPOS-00207',
'SRG-OS-000458-GPOS-00203', 'SRG-OS-000303-GPOS-00120',
'SRG-OS-000241-GPOS-00091', 'SRG-OS-000240-GPOS-00090',
'SRG-OS-000239-GPOS-00089']
  tag gid: 'V-219224'
  tag rid: 'SV-219224r508662_rule'
  tag stig_id: 'UBTU-18-010248'
  tag fix_id: 'F-20948r305001_fix'
  tag cci: ['SV-109779', 'V-100675', 'CCI-000172', 'CCI-001404', 'CCI-001405',
'CCI-001403', 'CCI-002130']
  tag nist: ['AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']

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
    describe ('Audit line(s) for ' + @audit_file + ' exist') do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end

