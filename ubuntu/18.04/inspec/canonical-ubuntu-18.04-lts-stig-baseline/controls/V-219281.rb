# encoding: UTF-8

control 'V-219281' do
  title "The Ubuntu operating system must prevent all software from executing
at higher privilege levels than users executing the software and the audit
system must be configured to audit the execution of privileged functions."
  desc  "In certain situations, software applications/programs need to execute
with elevated privileges to perform required functions. However, if the
privileges required for execution are at a higher level than the privileges
assigned to organizational users invoking such applications/programs, those
users are indirectly provided with greater privileges than assigned by the
organizations.

    Some programs and processes are required to operate at a higher privilege
level and therefore should be excluded from the organization-defined software
list after review.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system audits the execution of privilege
functions by auditing the \"execve\" system call.

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep execve

    -a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv
    -a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv
    -a always,exit -F arch=b32 -S execve -C uid!=euid -F key=execpriv
    -a always,exit -F arch=b32 -S execve -C gid!=egid -F key=execpriv

    If the command does not return lines that match the example or the lines
are commented out, this is a finding.

    Notes:
    For 32-bit architectures, only the 32-bit specific output lines from the
commands are required.
    The '-k' allows for specifying an arbitrary identifier and the string after
it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to audit the execution of all
privileged functions.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\"
file:

    -a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv
    -a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv
    -a always,exit -F arch=b32 -S execve -C uid!=euid -F key=execpriv
    -a always,exit -F arch=b32 -S execve -C gid!=egid -F key=execpriv

    Notes: For 32-bit architectures, only the 32-bit specific entries are
required.
    The \"root\" account must be used to view/edit any files in the
/etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag satisfies: ['SRG-OS-000326-GPOS-00126', 'SRG-OS-000327-GPOS-00127']
  tag gid: 'V-219281'
  tag rid: 'SV-219281r508662_rule'
  tag stig_id: 'UBTU-18-010358'
  tag fix_id: 'F-21005r305172_fix'
  tag cci: ['V-100785', 'SV-109889', 'CCI-002233', 'CCI-002234']
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

