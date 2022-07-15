control 'PHTN-30-000020' do
  title 'The Photon operating system must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc  'The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # auditctl -l | grep chmod

    Expected result:

    -a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod

    -a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F key=perm_mod

    -a always,exit -F arch=b32 -S chmod,fchmod,fchown,chown,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod

    -a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F key=perm_mod

    If the output does not match the expected result, this is a finding.

    Note: The auid!= parameter may display as 4294967295 or -1 which are equivalent.

    Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done in control PHTN-30-000013.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/rules.d/audit.STIG.rules

    Add the following lines:

    -a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
    -a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,fchmod,fchown,chown,fchownat,fchmodat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F key=perm_mod

    At the command line, execute the following command to load the new audit rules.

    # /sbin/augenrules --load

    Note: A new audit.STIG.rules file is provided as a supplemental document that can be placed in /etc/audit/rules.d that contains all rules needed for auditd.

    Note: An older audit.STIG.rules may exist if the file exists and references older \"GEN\" SRG IDs. This file can be removed and replaced as necessary with an updated one.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag satisfies: ['SRG-OS-000462-GPOS-00206', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000468-GPOS-00212']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000020'
  tag cci: ['CCI-000172', 'CCI-000172', 'CCI-002884', 'CCI-000172', 'CCI-000172']
  tag nist: ['AU-12 c', 'AU-12 c', 'MA-4 (1) (a)', 'AU-12 c', 'AU-12 c']

  describe auditd do
    its('lines') { should include /-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,fchownat,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod/ }
    its('lines') { should include /-a always,exit -F arch=b64 -S chmod,fchmod,chown,fchown,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F key=perm_mod/ }
    its('lines') { should include /-a always,exit -F arch=b32 -S chmod,fchmod,fchown,chown,fchownat,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod/ }
    its('lines') { should include /-a always,exit -F arch=b32 -S chmod,lchown,fchmod,fchown,chown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat -F key=perm_mod/ }
  end
end
