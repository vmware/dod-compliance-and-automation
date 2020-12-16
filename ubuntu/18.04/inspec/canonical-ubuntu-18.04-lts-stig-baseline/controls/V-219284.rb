# encoding: UTF-8

control 'V-219284' do
  title "The Ubuntu operating system must generate audit records when
successful/unsuccessful attempts to use fsetxattr system call."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system generates audit records when
successful/unsuccessful attempts to use fsetxattr system call.

    Check the configured audit rules with the following commands:

    # sudo auditctl -l | grep fsetxattr

    -a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=-1 -k
perm_chng
    -a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=-1 -k
perm_chng

    If the command does not return lines that match the example or the lines
are commented out, this is a finding.

    Note:
    For 32-bit architectures, only the 32-bit specific output lines from the
commands are required.
    The '-k' allows for specifying an arbitrary identifier and the string after
it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the audit system to generate audit records for
successful/unsuccessful attempts to use fsetxattr system call.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\"
file:

    -a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295
-k perm_chng
    -a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295
-k perm_chng

    Notes: For 32-bit architectures, only the 32-bit specific entries are
required.
    The \"root\" account must be used to view/edit any files in the
/etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000462-GPOS-00206'
  tag gid: 'V-219284'
  tag rid: 'SV-219284r508662_rule'
  tag stig_id: 'UBTU-18-010368'
  tag fix_id: 'F-21008r305181_fix'
  tag cci: ['SV-109895', 'V-100791', 'CCI-000172']
  tag nist: ['AU-12 c']

  if os.arch == 'x86_64'
    describe auditd.syscall('fsetxattr').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
  describe auditd.syscall('fsetxattr').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
end

