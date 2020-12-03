control 'V-219299' do
  title "The Ubuntu operating system must generate audit records when
    successful/unsuccessful attempts to use the kmod command."
  desc  "Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
    incident or identify those responsible for one.

    Audit records can be generated from various components within the
    information system (e.g., module or policy filter).

    The list of audited events is the set of events for which audits are to be
    generated. This set of events is typically a subset of the list of all events
    for which the system is capable of generating audit records.

    DoD has defined the list of events for which the Ubuntu operating system
    will provide an audit record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
    privileges, security objects, security levels, or categories of information
    (e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
    privileged activities or other system-level access, starting and ending time
    for user access to the system, concurrent logons from different workstations,
    successful and unsuccessful accesses to objects, all program initiations, and
    all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000477-GPOS-00222"
  tag "satisfies": nil
  tag "gid": 'V-219299'
  tag "rid": "SV-219299r381493_rule"
  tag "stig_id": "UBTU-18-010391"
  tag "fix_id": "F-21023r305226_fix"
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
  desc 'check', "Verify if the Ubuntu operating system is configured to audit the
    execution of the module management program \"kmod\".

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep kmod

    -w /bin/kmod -p x -k module

    If the command does not return a line, or the line is commented out, this is a finding.

    Note: The '-k' allows for specifying an arbitrary identifier and the string
    after it does not need to match the example output above.
  "
  desc 'fix', "Configure the Ubuntu operating system to audit the execution of
    the module management program \"kmod\".

    Add or update the following rule in the \"/etc/audit/rules.d/stig.rules\" file.

    -w /bin/kmod -p x -k modules

    Note:
    The \"root\" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  @audit_file = '/bin/kmod'

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
