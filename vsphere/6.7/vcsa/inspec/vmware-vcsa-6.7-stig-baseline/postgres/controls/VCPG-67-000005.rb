control 'VCPG-67-000005' do
  title "VMware Postgres database must protect log files from unauthorized
access and modification."
  desc  "If audit data were to become compromised, competent forensic analysis
and discovery of the true source of potentially malicious system activity would
be difficult, if not impossible, to achieve. In addition, access to audit
records provides information an attacker could potentially use to his or her
advantage.

    To ensure the veracity of audit data, the information system and/or the
application must protect audit information from any and all unauthorized
access. This includes read, write, copy, etc.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, enter the following command:

    # find /var/log/vmware/vpostgres/* -xdev -type f -a '(' -not -perm 600 -o
-not -user vpostgres -o -not -group users ')' -exec ls -ld {} \\;

    If any files are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, enter the following command:

    # chmod 600 <file>
    # chown vpostgres:users <file>

    Note: Replace <file> with the file with incorrect permissions.

    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
log_file_mode TO '0600';\"

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag satisfies: ['SRG-APP-000118-DB-000059', 'SRG-APP-000119-DB-000060',
'SRG-APP-000120-DB-000061']
  tag gid: 'V-239200'
  tag rid: 'SV-239200r717052_rule'
  tag stig_id: 'VCPG-67-000005'
  tag fix_id: 'F-42392r678972_fix'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_file_mode;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_log_file_mode')}" }
  end

  command("find '#{input('pg_log_dir')}'/* -xdev -type f").stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp 'vpostgres' }
      its('group') { should cmp 'users' }
    end
  end
end
