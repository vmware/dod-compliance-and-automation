control 'PHTN-30-000014' do
  title 'The Photon operating system audit log must log space limit problems to syslog.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

'
  desc 'check', 'At the command line, run the following command:

# grep "^space_left_action" /etc/audit/auditd.conf

Expected result:

space_left_action = SYSLOG

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/audit/auditd.conf

Ensure the "space_left_action" line is uncommented and set to the following:

space_left_action = SYSLOG

At the command line, run the following commands:

# killproc auditd -TERM
# systemctl start auditd'
  impact 0.5
  tag check_id: 'C-60166r887145_chk'
  tag severity: 'medium'
  tag gid: 'V-256491'
  tag rid: 'SV-256491r887147_rule'
  tag stig_id: 'PHTN-30-000014'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-60109r887146_fix'
  tag satisfies: ['SRG-OS-000046-GPOS-00022', 'SRG-OS-000344-GPOS-00135']
  tag cci: ['CCI-000139', 'CCI-001858']
  tag nist: ['AU-5 a', 'AU-5 (2)']

  describe auditd_conf do
    its('space_left_action') { should cmp 'SYSLOG' }
  end
end
