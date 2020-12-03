control 'V-219238' do
  title "The Ubuntu operating system must generate audit records for
    successful/unsuccessful
    uses of the su command."
  desc  "Without establishing what type of events occurred, it would be
    difficult to establish, correlate, and investigate the events leading up to an
    outage or attack.

    Audit record content that may be necessary to satisfy this requirement
    includes, for example, time stamps, source and destination addresses,
    user/process identifiers, event descriptions, success/fail indications,
    filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in the Ubuntu operating system
    audit logs provides a means of investigating an attack; recognizing resource
    utilization or capacity thresholds; or identifying an improperly configured
    Ubuntu operating system.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "satisfies": nil

  tag "gid": 'V-219238'
  tag "rid": "SV-219238r378727_rule"
  tag "stig_id": "UBTU-18-010315"
  tag "fix_id": "F-20962r305043_fix"
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
  desc 'check', "Verify if the Ubuntu operating system generates audit records when
    successful/unsuccessful attempts to use the \"su\" command occur.

    Check the configured audit rules with the following commands:

    # sudo auditctl -l | grep '/bin/su'

    -a always,exit -F path=/bin/su -F perm=x -F auid=1000 -F auid!=4294967295 -k privileged-priv_change

    If the command does not return lines that match the example or the lines are commented out,
    this is a finding.

    Note: The '-k' allows for specifying an arbitrary identifier and the string after it
    does not need to match the example output above.
  "
  desc 'fix', "Configure the Ubuntu operating system to generate audit records when
    successful/unsuccessful attempts to use the \"su\" command occur.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\" file:

    -a always,exit -F path=/bin/su -F perm=x -F auid=1000 -F auid!=4294967295 -k privileged-priv_change

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load

    Note:
    The \"root\" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.
  "
  @audit_file = '/bin/su'

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
