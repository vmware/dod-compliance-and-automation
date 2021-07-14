# encoding: UTF-8

control 'V-219297' do
  title "The Ubuntu operating system must generate records for
successful/unsuccessful uses of delete_module syscall and when unloading
dynamic kernel modules."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

  "
  desc  'rationale', ''
  desc  'check', "
    Verify if the Ubuntu operating system is configured to audit the
\"delete_module\" syscall, by running the following command:

    # sudo auditctl -l | egrep delete_module

    -a always,exit -F arch=b64 -S delete_module -F key=modules
    -a always,exit -F arch=b32 -S delete_module -F key=modules

    If the command does not return lines that match the example or the lines
are commented out, this is a finding.

    Notes:
    For 32-bit architectures, only the 32-bit specific output lines from the
commands are required.
    The '-k' allows for specifying an arbitrary identifier and the string after
it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to generate an audit event for any
use of the delete_module system call.

    Add or update the following rule in the \"/etc/audit/rules.d/stig.rules\"
file.

    -a always,exit -F arch=b32 -S delete_module -F key=modules
    -a always,exit -F arch=b64 -S delete_module -F key=modules

    Notes: For 32-bit architectures, only the 32-bit specific entries are
required.
    The \"root\" account must be used to view/edit any files in the
/etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000471-GPOS-00216']
  tag gid: 'V-219297'
  tag rid: 'SV-219297r648694_rule'
  tag stig_id: 'UBTU-18-010388'
  tag fix_id: 'F-21021r305220_fix'
  tag cci: ['CCI-000172']
  tag legacy: ['V-100817', 'SV-109921']
  tag nist: ['AU-12 c']

  if os.arch == 'x86_64'
    describe auditd.syscall('delete_module').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
      its('fields.flatten.uniq') {  should include "auid>=#{login_defs.UID_MIN}" }
    end
  end
  describe auditd.syscall('delete_module').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
    its('fields.flatten.uniq') {  should include "auid>=#{login_defs.UID_MIN}" }
  end
end

