# encoding: UTF-8

control 'V-219290' do
  title "The Ubuntu operating system must generate audit records when
successful/unsuccessful use of renameat system call."
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
successful/unsuccessful use of renameat system call.

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep renameat

    -a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=-1 -k delete
    -a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=-1 -k delete

    If the command does not return lines that match the example or the lines
are commented out, this is a finding.

    Notes:
    For 32-bit architectures, only the 32-bit specific output lines from the
commands are required.
    The '-k' allows for specifying an arbitrary identifier and the string after
it does not need to match the example output above.
  "
  desc  'fix', "
    Configure the audit system to generate audit events when
successful/unsuccessful use of the renameat system call.

    Add or update the following rules in the \"/etc/audit/rules.d/stig.rules\"
file:

    -a always,exit -F arch=b64 -S renameat -Fauid>=1000 -F auid!=4294967295 -k
delete
    -a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=4294967295 -k
delete

    Notes: For 32-bit architectures, only the 32-bit specific entries are
required.
    The \"root\" account must be used to view/edit any files in the
/etc/audit/rules.d/ directory.

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000468-GPOS-00212'
  tag gid: 'V-219290'
  tag rid: 'SV-219290r508662_rule'
  tag stig_id: 'UBTU-18-010378'
  tag fix_id: 'F-21014r305199_fix'
  tag cci: ['V-100803', 'SV-109907', 'CCI-000172']
  tag nist: ['AU-12 c']

  if os.arch == "x86_64"
    describe auditd.syscall("renameat").where { arch == "b64" } do
      its("action.uniq") { should eq ["always"] }
      its("list.uniq") { should eq ["exit"] }
    end
  end
  describe auditd.syscall("renameat").where { arch == "b32" } do
    its("action.uniq") { should eq ["always"] }
    its("list.uniq") { should eq ["exit"] }
  end
end

