control 'V-219284' do
  title "The Ubuntu operating system must generate audit records when
    successful/unsuccessful attempts to use fsetxattr system call."
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
  tag "gtitle": "SRG-OS-000462-GPOS-00206"
  tag "satisfies": nil

  tag "gid": 'V-219284'
  tag "rid": "SV-219284r381448_rule"
  tag "stig_id": "UBTU-18-010368"
  tag "fix_id": "F-21008r305181_fix"
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
  desc 'check', "Verify the Ubuntu operating system generates audit records when
    successful/unsuccessful attempts to use fsetxattr system call.

    Check the configured audit rules with the following commands:

    # sudo auditctl -l | grep fsetxattr

    -a always,exit -F arch=b64 -S fsetxattr -F auid=1000 -F auid!=-1 -k perm_chng
    -a always,exit -F arch=b32 -S fsetxattr -F auid=1000 -F auid!=-1 -k perm_chng

    If the command does not return lines that match the example or the lines are
    commented out, this is a finding.

    Note:
    For 32-bit architectures, only the 32-bit specific output lines from the
    commands are required.
    The '-k' allows for specifying an arbitrary identifier and the string after
    it does not need to match the example output above.
  "
  desc 'fix', "Configure the audit system to generate audit records for
    successful/unsuccessful attempts to use fsetxattr system call.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\" file:

    -a always,exit -F arch=b64 -S fsetxattr -F auid=1000 -F auid!=4294967295 -k perm_chng
    -a always,exit -F arch=b32 -S fsetxattr -F auid=1000 -F auid!=4294967295 -k perm_chng

    Notes: For 32-bit architectures, only the 32-bit specific entries are required.
    The \"root\" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  if os.arch == 'x86_64'
    describe auditd.syscall('fsetxattr').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
  describe auditd.syscall('fsetxattr').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
end
