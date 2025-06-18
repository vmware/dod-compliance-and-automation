control 'UBTU-22-654230' do
  title 'Ubuntu 22.04 LTS must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions.'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.

Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.

'
  desc 'check', 'Verify Ubuntu 22.04 LTS audits the execution of privilege functions by auditing the "execve" system call by using the following command:

     $ sudo auditctl -l | grep execve
     -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv
     -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv
     -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv
     -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv

If the command does not return lines that match the example or the lines are commented out, this is a finding.

Note: The "key=" value is arbitrary and can be different from the example output above.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to audit the execution of all privileged functions.

Add or modify the following lines in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv

To reload the rules file, issue the following command:

     $ sudo augenrules --load

Note: The "-k <keyname>" at the end of the line gives the rule a unique meaning to help during an audit investigation. The <keyname> does not need to match the example above.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64377r953755_chk'
  tag severity: 'medium'
  tag gid: 'V-260648'
  tag rid: 'SV-260648r958730_rule'
  tag stig_id: 'UBTU-22-654230'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-64285r953756_fix'
  tag satisfies: ['SRG-OS-000326-GPOS-00126', 'SRG-OS-000327-GPOS-00127']
  tag 'documentable'
  tag cci: ['CCI-002233', 'CCI-002234']
  tag nist: ['AC-6 (8)', 'AC-6 (9)']

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
