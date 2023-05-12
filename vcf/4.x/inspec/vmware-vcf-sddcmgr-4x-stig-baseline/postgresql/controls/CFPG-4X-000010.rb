control 'CFPG-4X-000010' do
  title 'The SDDC Manager PostgreSQL service must be configured to protect log files from unauthorized read access.'
  desc  "
    If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

    To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # psql -h localhost -U postgres -A -t -c \"SHOW log_file_mode\"

    Expected result:

    0600

    If the output does not match the expected result, this is a finding.

    At the command prompt, run the following command to find the configured log destination:

    # psql -h localhost -U postgres -A -t -c \"SHOW log_directory\"

    After finding the log destination, run the following command:

    find <log dir>/* -xdev -type f -a '(' -not -perm 600 -o -not -user postgres -o -not -group users ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, rune the following commands:

    # psql -h localhost -U postgres -c \"ALTER SYSTEM SET log_file_mode = '0600';\"
    # psql -h localhost -U postgres -c \"SELECT pg_reload_conf();\"

    At the command prompt, run the following commands:

    # chmod 600 <file>
    # chown postgres:users <file>

    Note: Replace <file> with the file with incorrect permissions.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag satisfies: ['SRG-APP-000267-DB-000163', 'SRG-APP-000357-DB-000316']
  tag gid: 'V-CFPG-4X-000010'
  tag rid: 'SV-CFPG-4X-000010'
  tag stig_id: 'CFPG-4X-000010'
  tag cci: ['CCI-000162', 'CCI-001314', 'CCI-001849']
  tag nist: ['AU-4', 'AU-9', 'SI-11 b']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_file_mode;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_log_file_mode')}" }
  end

  command("find '#{input('pg_log_dir')}'/* -xdev -type f").stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp 'postgres' }
      its('group') { should cmp 'users' }
    end
  end
end
