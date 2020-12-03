control 'V-219214' do
  title "The Ubuntu operating system must generate audit records for the use and modification
    of faillog file."
  desc  "Without generating audit records that are specific to the security and
    mission needs of the organization, it would be difficult to establish,
    correlate, and investigate the events relating to an incident or identify those
    responsible for one.

    Audit records can be generated from various components within the
    information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "satisfies": nil
  tag "gid": 'V-219214'
  tag "rid": "SV-219214r378727_rule"
  tag "stig_id": "UBTU-18-010202"
  tag "fix_id": "F-20938r304971_fix"
  tag "cci": [ "CCI-000172" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify the Ubuntu operating system generates an audit record when
    successful/unsuccessful modifications to the \"faillog\" file occur.

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep faillog

    -w /var/log/faillog -p wa -k logins

    If the command does not return a line that matches the example or the line is commented
    out, this is a finding.

    Note: The '-k' allows for specifying an arbitrary identifier and the string after it does
    not need to match the example output above.
  "
  desc 'fix', "Configure the audit system to generate an audit event for any
    successful/unsuccessful modifications to the \"faillog\" file occur.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\" file:

    -w /var/log/faillog -p wa -k logins

    Note:
    The \"root\" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
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
    describe ('Audit line(s) for ' + @audit_file + ' exist') do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end
