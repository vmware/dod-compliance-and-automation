control 'VCFI-9X-000020' do
  title 'The VMware Cloud Foundation Operations PostgreSQL service must be configured to protect log files from unauthorized access.'
  desc  "
    If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

    To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the default log file permissions and permissions on existing log files.

    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c 'SHOW log_file_mode;'\"

    Example result:

    0600

    If the \"log_file_mode\" setting is not configured to \"0600\", this is a finding.

    As a database administrator, perform the following at the command prompt:

    # find /var/log/postgres/* -xdev -type f -a '(' -not -perm 600 -o -not -user postgres -o -not -group users ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"ALTER SYSTEM SET log_file_mode = '0600';\\\"\"

    Reload the PostgreSQL service by running the following command:

    # systemctl restart vpostgres-repl.service

    At the command prompt, enter the following commands:

    # chmod 600 <file>
    # chown postgres:users <file>

    Note: Replace <file> with the file with incorrect permissions.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag satisfies: ['SRG-APP-000119-DB-000060', 'SRG-APP-000120-DB-000061']
  tag gid: 'V-VCFI-9X-000020'
  tag rid: 'SV-VCFI-9X-000020'
  tag stig_id: 'VCFI-9X-000020'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a']

  pg_log_dir = input('pg_log_dir')
  pg_owner = input('pg_owner')
  pg_group = input('pg_group')

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}", "#{input('postgres_db_port')}")

  describe sql.query('SHOW log_file_mode;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp '0600' }
  end

  describe sql.query('SHOW log_directory;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp pg_log_dir }
  end

  logfiles = command("find #{pg_log_dir}/* -xdev -type f -a '(' -not -perm 600 -o -not -user #{pg_owner} -o -not -group #{pg_group} ')'")

  logfiles.stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp pg_owner }
      its('group') { should cmp pg_group }
    end
  end
end
