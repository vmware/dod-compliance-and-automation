control 'PHTN-40-000173' do
  title 'The Photon operating system must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'At the command line, run the following command to verify an audit rule exists to audit logon attempts:

# auditctl -l | grep -E "faillog|lastlog|tallylog"

Expected result:

-w /var/log/faillog -p wa -k logons
-w /var/log/lastlog -p wa -k logons
-w /var/log/tallylog -p wa -k logons

If the output does not match the expected result, this is a finding.

Note: This check depends on the "auditd" service to be in a running state for accurate results. The "auditd" service is enabled in control PHTN-40-000016.'
  desc 'fix', 'Navigate to and open:

/etc/audit/rules.d/audit.STIG.rules

Add or update the following lines:

-w /var/log/faillog -p wa -k logons
-w /var/log/lastlog -p wa -k logons
-w /var/log/tallylog -p wa -k logons

At the command line, run the following command to load the new audit rules:

# /sbin/augenrules --load

Note: An "audit.STIG.rules" file is provided with this guidance for placement in "/etc/audit/rules.d" that contains all rules needed for auditd.

Note: An older "audit.STIG.rules" may exist and may reference older "GEN" SRG IDs. This file can be removed and replaced as necessary with an updated one.'
  impact 0.5
  tag check_id: 'C-62590r933609_chk'
  tag severity: 'medium'
  tag gid: 'V-258850'
  tag rid: 'SV-258850r991578_rule'
  tag stig_id: 'PHTN-40-000173'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-62499r933610_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe auditd.file('/var/log/faillog') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'logons' }
  end
  describe auditd.file('/var/log/lastlog') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'logons' }
  end
  describe auditd.file('/var/log/tallylog') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'logons' }
  end
end
