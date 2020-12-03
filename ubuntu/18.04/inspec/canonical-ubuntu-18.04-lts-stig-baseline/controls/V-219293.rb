control 'V-219293' do
  title "The Ubuntu operating system must generate audit records when successful/unsuccessful
    uses of the truncate system call."
  desc  "Without generating audit records that are specific to the security and
    mission needs of the organization, it would be difficult to establish,
    correlate, and investigate the events relating to an incident or identify those
    responsible for one.

    Audit records can be generated from various components within the
    information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000474-GPOS-00219"
  tag "satisfies": nil
  tag "gid": 'V-219293'
  tag "rid": "SV-219293r381484_rule"
  tag "stig_id": "UBTU-18-010382"
  tag "fix_id": "F-21017r305208_fix"
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
  desc 'check', "Verify the Ubuntu operating system generates an audit record
    when unsuccessful attempts to use the \"truncate\" system call occur.

    Check the configured audit rules with the following commands:

    # sudo auditctl -l | grep truncate
    -a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid=1000 -F auid!=-1 -k perm_access
    -a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid=1000 -F auid!=-1 -k perm_access
    -a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid=1000 -F auid!=-1 -k perm_access
    -a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid=1000 -F auid!=-1 -k perm_access

    If the command does not return lines that match the example or the lines are
    commented out, this is a finding.

    Notes:
    For 32-bit architectures, only the 32-bit specific output lines from the commands are required.
    The '-k' allows for specifying an arbitrary identifier and the string after it
    does not need to match the example output above.
  "
  desc 'fix', "Configure the audit system to generate an audit event for any
    unsuccessful use of the \"truncate\" system call.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\" file:

    -a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid=1000 -F auid!=4294967295 -k perm_access
    -a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid=1000 -F auid!=4294967295 -k perm_access
    -a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid=1000 -F auid!=4294967295 -k perm_access
    -a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid=1000 -F auid!=4294967295 -k perm_access

    Notes: For 32-bit architectures, only the 32-bit specific entries are required.
    The \"root\" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  if os.arch == 'x86_64'
    describe auditd.syscall('truncate').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
      its('exit.uniq') { should include '-EPERM' }
    end
    describe auditd.syscall('truncate').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
      its('exit.uniq') { should include '-EACCES' }
    end
  end
  describe auditd.syscall('truncate').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
    its('exit.uniq') { should include '-EPERM' }
  end
  describe auditd.syscall('truncate').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
    its('exit.uniq') { should include '-EACCES' }
  end
end
