control 'V-219281' do
  title "The Ubuntu operating system must prevent all software from executing at
    higher privilege levels than users executing the software and the audit system must
    be configured to audit the execution of privileged functions."
  desc  "Misuse of privileged functions, either intentionally or
    unintentionally by authorized users, or by unauthorized external entities that
    have compromised information system accounts, is a serious and ongoing concern
    and can have significant adverse impacts on organizations. Auditing the use of
    privileged functions is one way to detect such misuse and identify the risk
    from insider threats and the advanced persistent threat.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000326-GPOS-00126"
  tag "satisfies": nil
  tag "gid": 'V-219281'
  tag "rid": "SV-219281r379597_rule"
  tag "stig_id": "UBTU-18-010358"
  tag "fix_id": "F-21005r305172_fix"
  tag "cci": [ "CCI-002233","CCI-002234" ]
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
  desc 'check', "Verify the Ubuntu operating system audits the execution of privilege
    functions by auditing the \"execve\" system call.

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep execve

    -a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv
    -a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv
    -a always,exit -F arch=b32 -S execve -C uid!=euid -F key=execpriv
    -a always,exit -F arch=b32 -S execve -C gid!=egid -F key=execpriv

    If the command does not return lines that match the example or the lines are
    commented out, this is a finding.

    Notes:
    For 32-bit architectures, only the 32-bit specific output lines from the commands are required.
    The '-k' allows for specifying an arbitrary identifier and the string after it
    does not need to match the example output above.
  "
  desc 'fix', "Configure the Ubuntu operating system to audit the execution
    of all privileged functions.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\" file:

    -a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv
    -a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv
    -a always,exit -F arch=b32 -S execve -C uid!=euid -F key=execpriv
    -a always,exit -F arch=b32 -S execve -C gid!=egid -F key=execpriv

    Notes: For 32-bit architectures, only the 32-bit specific entries are required.
    The \"root\" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  if os.arch == 'x86_64'
    describe auditd.syscall('execve').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
  describe auditd.syscall('execve').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
end
