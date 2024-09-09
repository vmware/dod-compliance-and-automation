control 'PSQL-00-000032' do
  title 'The SDDC Manager PostgreSQL service must not load unused database components, software, and database objects.'
  desc  "
    Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

    It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.

    DBMSs must adhere to the principles of least functionality by providing only essential capabilities.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -c \"select * from pg_extension where extname != 'plpgsql'\"

    If any extensions exist that are not approved, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # /usr/pgsql/13/bin/psql -h localhost -U postgres -c \"DROP EXTENSION <extension name>\"

    Note: It is recommended that plpgsql not be removed.

    Reload the PostgreSQL service by running the following command:

    # systemctl restart postgres
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag satisfies: ['SRG-APP-000141-DB-000093']
  tag gid: 'V-PSQL-00-000032'
  tag rid: 'SV-PSQL-00-000032'
  tag stig_id: 'PSQL-00-000032'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  pg_approved_extensions = input('pg_approved_extensions')

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sql.query('select extname from pg_extension;', ["#{input('postgres_default_db')}"]).output.split.each do |ext|
    describe ext do
      it { should be_in pg_approved_extensions }
    end
  end
end
