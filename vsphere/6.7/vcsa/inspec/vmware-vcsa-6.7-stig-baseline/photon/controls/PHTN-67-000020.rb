control "PHTN-67-000020" do
  title "The Photon operating system must generate audit records when
successful/unsuccessful attempts to access privileges occur."
  desc  "The changing of file permissions could indicate that a user is
attempting to gain access to information that would otherwise be disallowed.
Auditing DAC modifications can facilitate the identification of patterns of
abuse among both authorized and unauthorized users.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep chmod

    Expected result:

    -a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,fchownat,fchmodat
-F auid>=1000 -F auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b64 -S
chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat
-F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,fchmod,fchown,chown,fchownat,fchmodat
-F auid>=1000 -F auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b32 -S
chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat
-F key=perm_mod

    If the output does not match the expected result, this is a finding.

    Note: This check depends on the auditd service to be in a running state for
accurate results. Enabling the auditd service is done as part of a separate
control.
  "
  desc  'fix', "
    Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the
following lines:

    -a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,fchownat,fchmodat
-F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b64 -S
chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat
-k perm_mod
    -a always,exit -F arch=b32 -S chmod,fchmod,fchown,chown,fchownat,fchmodat
-F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S
chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat
-k perm_mod

    At the command line, execute the following command:

    # /sbin/augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000462-GPOS-00206']
  tag gid: 'V-239092'
  tag rid: 'SV-239092r816603_rule'
  tag stig_id: 'PHTN-67-000020'
  tag fix_id: 'F-42262r816602_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe auditd do
    its("lines") { should include %r{-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,fchownat,fchmodat -F auid>=1000 -F auid!=-1} }
    its("lines") { should include %r{-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat} }
    its("lines") { should include %r{-a always,exit -F arch=b32 -S chmod,fchmod,fchown,chown,fchownat,fchmodat -F auid>=1000 -F auid!=-1} }
    its("lines") { should include %r{-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat} }
  end

end

