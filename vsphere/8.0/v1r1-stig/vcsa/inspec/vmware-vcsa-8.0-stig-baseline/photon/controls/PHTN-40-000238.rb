control 'PHTN-40-000238' do
  title 'The Photon operating system must generate audit records for all access and modifications to the opasswd file.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'At the command line, run the following command to verify an audit rule exists to audit the opasswd file:

# auditctl -l | grep -E /etc/security/opasswd

Expected result:

-w /etc/security/opasswd -p wa -k opasswd

If the opasswd file is not monitored for access or writes, this is a finding.

Note: This check depends on the "auditd" service to be in a running state for accurate results. The "auditd" service is enabled in control PHTN-40-000016.'
  desc 'fix', 'Navigate to and open:

/etc/audit/rules.d/audit.STIG.rules

Add or update the following lines:

-w /etc/security/opasswd -p wa -k opasswd

At the command line, run the following command to load the new audit rules:

# /sbin/augenrules --load

Note: An "audit.STIG.rules" file is provided with this guidance for placement in "/etc/audit/rules.d" that contains all rules needed for auditd.

Note: An older "audit.STIG.rules" may exist and may reference older "GEN" SRG IDs. This file can be removed and replaced as necessary with an updated one.'
  impact 0.5
  tag check_id: 'C-62639r933756_chk'
  tag severity: 'medium'
  tag gid: 'V-258899'
  tag rid: 'SV-258899r933758_rule'
  tag stig_id: 'PHTN-40-000238'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62548r933757_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe auditd.file('/etc/security/opasswd') do
    its('permissions') { should include ['w', 'a'] }
    its('key') { should cmp 'opasswd' }
  end
end
