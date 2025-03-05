control 'PHTN-40-000078' do
  title 'The Photon operating system must audit all account removal actions.'
  desc 'When operating system accounts are removed, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the operating system processes themselves. In order to detect and respond to events affecting user accessibility and system processing, operating systems must audit account removal actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.'
  desc 'check', 'At the command line, run the following command to verify an audit rule exists to audit account removals:

# auditctl -l | grep -E "(userdel|groupdel)"

Example result:

-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel

If either "userdel" or "groupdel" are not listed with a permissions filter of at least "x", this is a finding.

Note: This check depends on the "auditd" service to be in a running state for accurate results. The "auditd" service is enabled in control PHTN-40-000016.'
  desc 'fix', 'Navigate to and open:

/etc/audit/rules.d/audit.STIG.rules

Add or update the following lines:

-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel

At the command line, run the following command to load the new audit rules:

# /sbin/augenrules --load

Note: An "audit.STIG.rules" file is provided with this guidance for placement in "/etc/audit/rules.d" that contains all rules needed for auditd.

Note: An older "audit.STIG.rules" may exist and may reference older "GEN" SRG IDs. This file can be removed and replaced as necessary with an updated one.'
  impact 0.5
  tag check_id: 'C-62574r933561_chk'
  tag severity: 'medium'
  tag gid: 'V-258834'
  tag rid: 'SV-258834r991553_rule'
  tag stig_id: 'PHTN-40-000078'
  tag gtitle: 'SRG-OS-000241-GPOS-00091'
  tag fix_id: 'F-62483r933562_fix'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']

  describe auditd.file('/usr/sbin/userdel') do
    its('permissions') { should include ['x'] }
    its('key') { should cmp 'userdel' }
  end
  describe auditd.file('/usr/sbin/groupdel') do
    its('permissions') { should include ['x'] }
    its('key') { should cmp 'groupdel' }
  end
end
