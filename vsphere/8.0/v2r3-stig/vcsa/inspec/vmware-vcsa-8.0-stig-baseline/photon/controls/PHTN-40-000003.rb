control 'PHTN-40-000003' do
  title 'The Photon operating system must audit all account creations.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.'
  desc 'check', 'At the command line, run the following command to verify an audit rule exists to audit account creations:

# auditctl -l | grep -E "(useradd|groupadd)"

Example result:

-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd

If either "useradd" or "groupadd" are not listed with a permissions filter of at least "x", this is a finding.

Note: This check depends on the "auditd" service to be in a running state for accurate results. The "auditd" service is enabled in control PHTN-40-000016.'
  desc 'fix', 'Navigate to and open:

/etc/audit/rules.d/audit.STIG.rules

Add or update the following lines:

-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd

At the command line, run the following command to load the new audit rules:

# /sbin/augenrules --load

Note: An "audit.STIG.rules" file is provided with this guidance for placement in "/etc/audit/rules.d" that contains all rules needed for auditd.

Note: An older "audit.STIG.rules" may exist and may reference older "GEN" SRG IDs. This file can be removed and replaced as necessary with an updated one.'
  impact 0.5
  tag check_id: 'C-62541r933462_chk'
  tag severity: 'medium'
  tag gid: 'V-258801'
  tag rid: 'SV-258801r958368_rule'
  tag stig_id: 'PHTN-40-000003'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-62450r933463_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000476-GPOS-00221']
  tag cci: ['CCI-000018', 'CCI-000172']
  tag nist: ['AC-2 (4)', 'AU-12 c']

  describe auditd.file('/usr/sbin/useradd') do
    its('permissions') { should include ['x'] }
    its('key') { should cmp 'useradd' }
  end
  describe auditd.file('/usr/sbin/groupadd') do
    its('permissions') { should include ['x'] }
    its('key') { should cmp 'groupadd' }
  end
end
