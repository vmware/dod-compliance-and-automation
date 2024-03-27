control 'PHTN-50-000031' do
  title 'The Photon operating system must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc  'The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify an audit rule exists to audit account creations:

    # auditctl -l | grep chmod

    Expected result:

    -a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the \"auditd\" service to be in a running state for accurate results. The \"auditd\" service is enabled in control PHTN-50-000016.

    Note: auid!=-1, auid!=4294967295, auid!=unset are functionally equivalent in this check and the output of the above commands may be displayed in either format.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add or update the following lines:

    -a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod

    At the command line, run the following command to load the new audit rules:

    # /sbin/augenrules --load

    Note: An \"audit.STIG.rules\" file is provided with this guidance for placement in \"/etc/audit/rules.d\" that contains all rules needed for auditd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag satisfies: ['SRG-OS-000462-GPOS-00206', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000474-GPOS-00219']
  tag gid: 'V-PHTN-50-000031'
  tag rid: 'SV-PHTN-50-000031'
  tag stig_id: 'PHTN-50-000031'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe auditd do
    its('lines') { should include /-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod/ }
    its('lines') { should include /-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod/ }
    its('lines') { should include /-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod/ }
    its('lines') { should include /-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F auid=0 -F key=perm_mod/ }
  end
end
