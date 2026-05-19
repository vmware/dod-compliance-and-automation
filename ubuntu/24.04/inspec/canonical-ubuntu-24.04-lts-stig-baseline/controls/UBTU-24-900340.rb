control 'UBTU-24-900340' do
  title 'Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module syscalls.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.

'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates an audit record for any successful/unsuccessful attempts to use the "init_module" and "finit_module" syscalls with the following command:

$ sudo auditctl -l | grep init_module
-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng

If the command does not return audit rules for the "init_module" and "finit_module" syscalls or the lines are commented out, this is a finding.

Notes:
- For 32-bit architectures, only the 32-bit specific output lines from the commands are required.
- The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "init_module" and "finit_module" syscalls.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng

Note: For 32-bit architectures, only the 32-bit specific entries are required.

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74838r1068383_chk'
  tag severity: 'medium'
  tag gid: 'V-270805'
  tag rid: 'SV-270805r1068384_rule'
  tag stig_id: 'UBTU-24-900340'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-74739r1066903_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000471-GPOS-00216']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  if os.arch == 'x86_64'
    describe auditd.syscall('init_module').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
    describe auditd.syscall('finit_module').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
  describe auditd.syscall('finit_module').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
end
