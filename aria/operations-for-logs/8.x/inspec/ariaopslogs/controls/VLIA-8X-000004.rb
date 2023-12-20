control 'VLIA-8X-000004' do
  title 'VMware Aria Operations for Logs must protect audit information from unauthorized read access.'
  desc  "
    If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult if not impossible to achieve. In addition, access to audit records provides information attackers could potentially use to their advantage.

    To ensure the validity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, and copy access.

    This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions, controlling number of log files and repositories, and restricting access to the location of log file repositories.

    Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring audit information is protected from unauthorized access.

    Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # stat -c \"%a:%U:%G\" /var/log/loginsight/audit.log

    Expected result:

    640:root:root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command(s):

    # chown root:root /var/log/loginsight/audit.log

    # chmod 640 /var/log/loginsight/audit.log
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-AU-000100'
  tag satisfies: %w(SRG-APP-000119-AU-000110 SRG-APP-000120-AU-000120 SRG-APP-000121-AU-000130 SRG-APP-000122-AU-000140 SRG-APP-000123-AU-000150)
  tag gid: 'V-VLIA-8X-000004'
  tag rid: 'SV-VLIA-8X-000004'
  tag stig_id: 'VLIA-8X-000004'
  tag cci: %w(CCI-000162 CCI-000163 CCI-000164 CCI-001493 CCI-001494 CCI-001495)
  tag nist: ['AU-9']

  describe file('/var/log/loginsight/audit.log') do
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0640') }
  end
end
