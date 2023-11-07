control 'PHTN-40-000019' do
  title 'The Photon operating system must be configured to audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing all actions by superusers is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'At the command line, run the following command to verify audit rules exist to audit privileged functions:

# auditctl -l | grep execve

Expected result:

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv

If the output does not match the expected result, this is a finding.

Note: This check depends on the "auditd" service to be in a running state for accurate results. The "auditd" service is enabled in control PHTN-40-000016.'
  desc 'fix', 'Navigate to and open:

/etc/audit/rules.d/audit.STIG.rules

Add or update the following lines:

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv

At the command line, run the following command to load the new audit rules:

# /sbin/augenrules --load

Note: An "audit.STIG.rules" file is provided with this guidance for placement in "/etc/audit/rules.d" that contains all rules needed for auditd.

Note: An older "audit.STIG.rules" may exist and may reference older "GEN" SRG IDs. This file can be removed and replaced as necessary with an updated one.'
  impact 0.5
  tag check_id: 'C-62549r933486_chk'
  tag severity: 'medium'
  tag gid: 'V-258809'
  tag rid: 'SV-258809r933488_rule'
  tag stig_id: 'PHTN-40-000019'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-62458r933487_fix'
  tag satisfies: ['SRG-OS-000042-GPOS-00020', 'SRG-OS-000326-GPOS-00126']
  tag cci: ['CCI-000135', 'CCI-002233']
  tag nist: ['AU-3 (1)', 'AC-6 (8)']

  describe auditd do
    its('lines') { should include /-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv/ }
    its('lines') { should include /-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv/ }
    its('lines') { should include /-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv/ }
    its('lines') { should include /-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv/ }
  end
end
