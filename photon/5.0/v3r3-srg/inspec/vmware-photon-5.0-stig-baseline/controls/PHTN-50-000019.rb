control 'PHTN-50-000019' do
  title 'The Photon operating system must be configured to audit the execution of privileged functions.'
  desc  'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing all actions by superusers is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify audit rules exist to audit privileged functions:

    # auditctl -l | grep execve

    Expected result:

    -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv
    -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv
    -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv
    -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the \"auditd\" service to be in a running state for accurate results. The \"auditd\" service is enabled in control PHTN-50-000016.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add or update the following lines:

    -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv
    -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv
    -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv
    -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv

    At the command line, run the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: An \"audit.STIG.rules\" file is provided with this guidance for placement in \"/etc/audit/rules.d\" that contains all rules needed for auditd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag satisfies: ['SRG-OS-000326-GPOS-00126']
  tag gid: 'V-PHTN-50-000019'
  tag rid: 'SV-PHTN-50-000019'
  tag stig_id: 'PHTN-50-000019'
  tag cci: ['CCI-000135', 'CCI-002233']
  tag nist: ['AC-6 (8)', 'AU-3 (1)']

  describe auditd do
    its('lines') { should include /-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv/ }
    its('lines') { should include /-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv/ }
    its('lines') { should include /-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv/ }
    its('lines') { should include /-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv/ }
  end
end
