control 'V-219223' do
  title "The Ubuntu operating system must generate audit records for all account creations,
    modifications, disabling, and termination events that affect /etc/shadow."
  desc  "Without generating audit records that are specific to the security and
    mission needs of the organization, it would be difficult to establish,
    correlate, and investigate the events relating to an incident or identify those
    responsible for one.

    Audit records can be generated from various components within the
    information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000476-GPOS-00221"
  tag "satisfies": nil

  tag "gid": 'V-219223'
  tag "rid": "SV-219223r381490_rule"
  tag "stig_id": "UBTU-18-010247"
  tag "fix_id": "F-20947r304998_fix"
  tag "cci": [ "CCI-000172","CCI-001403","CCI-001404","CCI-001405","CCI-002130" ]
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
  desc 'check', "Verify the Ubuntu operating system generates audit records for all account
    creations, modifications, disabling, and termination events that affect /etc/shadow.

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep shadow

    -w /etc/shadow -p wa -k usergroup_modification

    If the command does not return a line that matches the example or the line is commented
    out, this is a finding.

    Note: The '-k' allows for specifying an arbitrary identifier and the string after it
    does not need to match the example output above.
  "

  desc 'fix', "Configure the Ubuntu operating system to generate audit records for all
    account creations, modifications, disabling, and termination events that affect /etc/shadow.

    Add or update the following rule to \"/etc/audit/rules.d/stig.rules\":

    -w /etc/shadow -p wa -k usergroup_modification

    Note:
    The \"root\" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "

  @audit_file = '/etc/shadow'
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
