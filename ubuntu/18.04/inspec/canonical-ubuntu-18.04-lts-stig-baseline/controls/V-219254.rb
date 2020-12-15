# encoding: UTF-8

control 'V-219254' do
  title "The Ubuntu operating system must generate audit records for
successful/unsuccessful uses of the chmod system call."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system generates an audit record when
successful/unsuccessful attempts to use the \"chmod\" system call.

    Check the configured audit rules with the following commands:

    # sudo auditctl -l | grep chmod

    -a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=-1 -k perm_chng
    -a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=-1 -k perm_chng

    If the command does not return lines that match the example or the lines
are commented out, this is a finding.

    Notes:
    For 32-bit architectures, only the 32-bit specific output lines from the
commands are required.
    The '-k' allows for specifying an arbitrary identifier and the string after
it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the audit system to generate an audit event for any
successful/unsuccessful use of the \"chmod\" system call.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\":

    -a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k
perm_chng
    -a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k
perm_chng

    Notes: For 32-bit architectures, only the 32-bit specific entries are
required.
    The \"root\" account must be used to view/edit any files in the
/etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000462-GPOS-00206']
  tag gid: 'V-219254'
  tag rid: 'SV-219254r508662_rule'
  tag stig_id: 'UBTU-18-010331'
  tag fix_id: 'F-20978r305091_fix'
  tag cci: ['V-100733', 'SV-109837', 'CCI-000172']
  tag nist: ['AU-12 c']

  if os.arch == 'x86_64'
    describe auditd.syscall('chmod').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
  describe auditd.syscall('chmod').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
end

