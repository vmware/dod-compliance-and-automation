control 'CFPG-4X-000020' do
  title 'Syslog must be configured to monitor PostgreSQL logs.'
  desc  "
    Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

    The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -v \"^#\" /etc/rsyslog.d/stig-services-postgres.conf

    Expected result:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
          File=\"/var/log/postgres/*.log\"
          Tag=\"vcf-postgres-runtime\"
          Severity=\"info\"
          Facility=\"local0\")

    If the file does not exist, this is a finding.

    If the output of the command does not match the expected result above, this is a finding.

    Note: The file parameter can be slightly different if the path is a dedicated log partition.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/rsyslog.d/stig-services-postgres.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
          File=\"/var/log/postgres/*.log\"
          Tag=\"vcf-postgres-runtime\"
          Severity=\"info\"
          Facility=\"local0\")

    At the command prompt, run the following command:

    # systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000356-DB-000314'
  tag satisfies: ['SRG-APP-000356-DB-000315', 'SRG-APP-000381-DB-000361', 'SRG-APP-000492-DB-000333', 'SRG-APP-000515-DB-000318']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFPG-4X-000020'
  tag cci: ['CCI-001844', 'CCI-001844', 'CCI-001814', 'CCI-000172', 'CCI-001851']
  tag nist: ['AU-3 (2)', 'AU-3 (2)', 'CM-5 (1)', 'AU-12 c', 'AU-4 (1)']

  goodcontent = inspec.profile.file('stig-services-postgres.conf')
  describe file('/etc/rsyslog.d/stig-services-postgres.conf') do
    its('content') { should eq goodcontent }
  end
end
