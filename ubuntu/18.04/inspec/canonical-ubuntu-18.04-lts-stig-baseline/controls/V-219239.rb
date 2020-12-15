# encoding: UTF-8

control 'V-219239' do
  title "The Ubuntu operating system must generate audit records for
successful/unsuccessful uses of the chfn command."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify if the Ubuntu operating system generates audit records when
successful/unsuccessful attempts to use of the \"chfn\" command occur.

    Check the configured audit rules with the following commands:

    # sudo auditctl -l | grep '/usr/bin/chfn'

    -a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -k
privileged-chfn

    If the command does not return lines that match the example or the lines
are commented out, this is a finding.

    Note: The '-k' allows for specifying an arbitrary identifier and the string
after it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the audit system to generate an audit event for any
successful/unsuccessful uses of the \"chfn\" command.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\"
file:

    -a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged-chfn

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load

    Note:
    The \"root\" account must be used to view/edit any files in the
/etc/audit/rules.d/ directory.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag gid: 'V-219239'
  tag rid: 'SV-219239r508662_rule'
  tag stig_id: 'UBTU-18-010316'
  tag fix_id: 'F-20963r305046_fix'
  tag cci: ['V-100705', 'SV-109809', 'CCI-000172']
  tag nist: ['AU-12 c']

  @audit_file = '/usr/bin/chfn'

  audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its('permissions') { should_not cmp [] }
      its('action') { should_not include 'never' }
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end

    @perms = auditd.file(@audit_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include 'x' }
      end
    end
  else
    describe ('Audit line(s) for ' + @audit_file + ' exist') do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end

