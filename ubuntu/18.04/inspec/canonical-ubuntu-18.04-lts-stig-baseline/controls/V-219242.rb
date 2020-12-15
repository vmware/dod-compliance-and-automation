# encoding: UTF-8

control 'V-219242' do
  title "The Ubuntu operating system must generate audit records for
successful/unsuccessful uses of the ssh-agent command."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system generates an audit record when
successful/unsuccessful attempts to use the \"ssh-agent\" command occur.

    Check the configured audit rules with the following commands:

    # sudo auditctl -l | grep '/usr/bin/ssh-agent'

    -a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F
auid!=-1 -k privileged-ssh

    If the command does not return lines that match the example or the lines
are commented out, this is a finding.

    Note: The '-k' allows for specifying an arbitrary identifier and the string
after it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the audit system to generate an audit event for any
successful/unsuccessful use of the \"ssh-agent\" command.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\"
file:

    -a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F
auid!=4294967295 -k privileged-ssh

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load

    Note:
    The \"root\" account must be used to view/edit any files in the
/etc/audit/rules.d/ directory.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag gid: 'V-219242'
  tag rid: 'SV-219242r508662_rule'
  tag stig_id: 'UBTU-18-010319'
  tag fix_id: 'F-20966r305055_fix'
  tag cci: ['SV-109815', 'V-100711', 'CCI-000172']
  tag nist: ['AU-12 c']

  @audit_file = '/usr/bin/ssh-agent'

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

