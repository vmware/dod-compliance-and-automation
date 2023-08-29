control 'WOAD-3X-000022' do
  title 'The Workspace ONE Access vPostgres instance must be configured to protect log files from unauthorized read access.'
  desc  "
    If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

    To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SHOW log_file_mode\"

    Expected result:

    0600

    If the output does not match the expected result, this is a finding.

    At the command prompt, execute the following command to find the configured log destination:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SHOW log_directory\"

    After finding the log destination, execute the following command:

    find <log dir>/* -xdev -type f -a '(' -not -perm 600 -o -not -user postgres -o -not -group users ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.

    Note: Log directory will be relative to /db/data by default for example: /db/data/pg_log

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following command(s):

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER SYSTEM SET log_file_mode = '0600';\"

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"SELECT pg_reload_conf();\"

    At the command prompt, enter the following command(s):

    # chmod 600 <file>
    # chown postgres:users <file>

    Note: Replace <file> with the file with incorrect permissions.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag satisfies: ['SRG-APP-000119-DB-000060', 'SRG-APP-000120-DB-000061', 'SRG-APP-000267-DB-000163']
  tag gid: 'V-WOAD-3X-000022'
  tag rid: 'SV-WOAD-3X-000022'
  tag stig_id: 'WOAD-3X-000022'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9', 'SI-11 b']

  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c "SHOW log_file_mode;"') do
      its('stdout.strip') { should cmp '0600' }
    end

    logdir = command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c "SHOW log_directory"').stdout.strip
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = 'SHOW log_file_mode;'

    describe sql.query(sqlquery) do
      its('output') { should cmp '0600' }
    end

    sqlquery2 = 'SHOW log_directory;'
    logdir = sql.query(sqlquery2).output
  end
  logfiles = command("find #{logdir} -type f -xdev").stdout
  if !logfiles.empty?
    logfiles.split.each do |fname|
      describe file(fname) do
        it { should_not be_more_permissive_than('0600') }
        its('owner') { should eq 'postgres' }
        its('group') { should eq 'users' }
      end
    end
  else
    describe 'No log files found...skipping.' do
      skip 'No log files found...skipping.'
    end
  end
end
