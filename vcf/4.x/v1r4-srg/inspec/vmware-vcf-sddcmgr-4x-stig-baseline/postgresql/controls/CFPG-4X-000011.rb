control 'CFPG-4X-000011' do
  title 'The SDDC Manager PostgreSQL service log directory must exist and be on a dedicated log partition.'
  desc  "
    If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

    To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command to find the configured log destination:

    # psql -h localhost -U postgres -A -t -c \"SHOW log_directory\"

    Expected result:

    /var/log/*

    If the output does not show the log file destination with /var/log in the path or another dedicated log partition, this is a finding.

    # ls -la <log_directory result>

    If the correctly defined directory specified in the first command does not exist, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following commands:

    # mkdir /var/log/postgres
    # chown postgres:users /var/log/postgres

    # psql -h localhost -U postgres -c \"ALTER SYSTEM SET log_directory = '/var/log/postgres';\"
    # psql -h localhost -U postgres -c \"SELECT pg_reload_conf();\"

    Note: Destination could be different and acceptable if under /var/log or another dedicated log partition.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag satisfies: ['SRG-APP-000119-DB-000060', 'SRG-APP-000120-DB-000061']
  tag gid: 'V-CFPG-4X-000011'
  tag rid: 'SV-CFPG-4X-000011'
  tag stig_id: 'CFPG-4X-000011'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW log_directory;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_log_dir')}" }
  end

  describe directory("#{input('pg_log_dir')}") do
    it { should exist }
  end
end
