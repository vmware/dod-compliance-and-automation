control 'V-219277' do
  title "The Ubuntu operating system must generate audit records for
    successful/unsuccessful uses of the pam_timestamp_check command."
  desc  "At a minimum, the organization must audit the full-text recording of
    privileged commands. The organization must maintain audit trails in sufficient
    detail to reconstruct events to determine the cause and impact of compromise.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "satisfies": nil
  tag "gid": 'V-219277'
  tag "rid": "SV-219277r378727_rule"
  tag "stig_id": "UBTU-18-010354"
  tag "fix_id": "F-21001r305160_fix"
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
  desc 'check', "Verify that an audit event is generated for any
    successful/unsuccessful use of the \"pam_timestamp_check\" command.

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep -w pam_timestamp_check

    -a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid=1000 -F auid!=-1 -k privileged-pam_timestamp_check

    If the command does not return a line that matches the example or the line is
    commented out, this is a finding.


    Note: The '-k' allows for specifying an arbitrary identifier and the string
    after it does not need to match the example output above.
  "
  desc 'fix', "Configure the audit system to generate an audit event for any
    successful/unsuccessful uses of the \"pam_timestamp_check\" command.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\" file:

    -a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid=1000 -F auid!=4294967295 -k privileged-pam_timestamp_check

    Note:
    The \"root\" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  @audit_file = '/usr/sbin/pam_timestamp_check'

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
    describe ('Audit line(s) for ' + @audit_file + ' exist') do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end
