control 'UBTU-24-909000' do
  title 'Ubuntu 24.04 LTS audit system must protect auditing rules from unauthorized change.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality. Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit Ubuntu 24.04 LTS system activity. In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. A system reboot would be noticeable, and a system administrator could then investigate the unauthorized changes.'
  desc 'check', %q(Verify the audit system prevents unauthorized changes to the rules with the following command:

$ grep -E '^-e 2' /etc/audit/audit.rules
-e 2

If the audit system is not set to be immutable by adding the "-e 2" option to the end of "/etc/audit/audit.rules", this is a finding.)
  desc 'fix', 'Configure the audit system to set the audit rules to be immutable by adding the following line to the end of "/etc/audit/rules.d/audit.rules":

-e 2'
  impact 0.5
  tag check_id: 'C-74865r1066983_chk'
  tag severity: 'medium'
  tag gid: 'V-270832'
  tag rid: 'SV-270832r1068399_rule'
  tag stig_id: 'UBTU-24-909000'
  tag gtitle: 'SRG-OS-000058-GPOS-00028'
  tag fix_id: 'F-74766r1068398_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']

  audit_rules_file = input('audit_rules_file')

  describe file(audit_rules_file) do
    it { should exist }
    its('content') { should match(/^-e\s+2$/) }
  end
end
