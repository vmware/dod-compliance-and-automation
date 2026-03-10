control 'UBTU-22-654175' do
  title 'Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module system calls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.

'
  desc 'check', 'Verify Ubuntu 22.04 LTS generates an audit record for any successful/unsuccessful attempts to use the "init_module" and "finit_module" syscalls by using the following command:

     $ sudo auditctl -l | grep init_module
     -a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng
     -a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng

If the command does not return audit rules for the "init_module" and "finit_module" syscalls or the lines are commented out, this is a finding.

Note: The "key=" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "init_module" and "finit_module" syscalls.

Add or modify the following lines in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64366r953722_chk'
  tag severity: 'medium'
  tag gid: 'V-260637'
  tag rid: 'SV-260637r958446_rule'
  tag stig_id: 'UBTU-22-654175'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-64274r953723_fix'
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
