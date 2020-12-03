control 'V-219243' do
  title "The Ubuntu operating system must generate audit records for
    successful/unsuccessful
    uses of the ssh-keysign command."
  desc  "Reconstruction of harmful events or forensic analysis is not possible
    if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
    privileged ssh commands. The organization must maintain audit trails in
    sufficient detail to reconstruct events to determine the cause and impact of
    compromise.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "satisfies": nil
  tag "gid": 'V-219243'
  tag "rid": "SV-219243r378727_rule"
  tag "stig_id": "UBTU-18-010320"
  tag "fix_id": "F-20967r305058_fix"
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
    successful/unsuccessful attempts to use the \"ssh-keysign\" command occur.

    Check the configured audit rules with the following commands:

    #sudo auditctl -l | grep ssh-keysign

    -a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid=1000 -F auid!=-1 -k privileged-ssh

    If the command does not return lines that match the example or the lines are commented
    out, this is a finding.

    Note: The '-k' allows for specifying an arbitrary identifier and the string after it
    does not need to match the example output above.
  "
  desc 'fix', "Configure the audit system to generate an audit event for any
    successful/unsuccessful use of the \"ssh-keysign\" command.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\" file:

    -a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid=1000 -F auid!=4294967295 -k privileged-ssh

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load

    Note:
    The \"root\" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.
  "
  @audit_file = '/usr/lib/openssh/ssh-keysign'

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
