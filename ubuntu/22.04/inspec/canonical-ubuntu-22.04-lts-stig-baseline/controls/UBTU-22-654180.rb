control 'UBTU-22-654180' do
  title 'Ubuntu 22.04 LTS must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.

'
  desc 'check', 'Verify Ubuntu 22.04 LTS generates an audit record upon successful/unsuccessful attempts to use the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" system calls by using the following command:

     $ sudo auditctl -l | grep xattr
     -a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
     -a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod
     -a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
     -a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod

If the command does not return audit rules for the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr" and "lremovexattr" syscalls or the lines are commented out, this is a finding.

Note: The "key=" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" system calls.

Add or modify the following lines in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64367r953725_chk'
  tag severity: 'medium'
  tag gid: 'V-260638'
  tag rid: 'SV-260638r958446_rule'
  tag stig_id: 'UBTU-22-654180'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-64275r953726_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000462-GPOS-00206']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  if os.arch == 'x86_64'
    describe auditd.syscall('setxattr').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
    describe auditd.syscall('fsetxattr').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
    describe auditd.syscall('lsetxattr').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
    describe auditd.syscall('removexattr').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
    describe auditd.syscall('fremovexattr').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
    describe auditd.syscall('lremovexattr').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
  describe auditd.syscall('setxattr').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  describe auditd.syscall('lsetxattr').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  describe auditd.syscall('fsetxattr').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  describe auditd.syscall('removexattr').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  describe auditd.syscall('fremovexattr').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  describe auditd.syscall('lremovexattr').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
end
