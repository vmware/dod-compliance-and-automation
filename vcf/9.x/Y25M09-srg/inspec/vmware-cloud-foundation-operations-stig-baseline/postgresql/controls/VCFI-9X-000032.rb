control 'VCFI-9X-000032' do
  title 'The VMware Cloud Foundation Operations PostgreSQL service must not load unused database components, software, and database objects.'
  desc  "
    Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

    It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.

    DBMSs must adhere to the principles of least functionality by providing only essential capabilities.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"select * from pg_extension where extname != 'plpgsql'\\\"\"

    If any extensions are output, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    $ su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c 'DROP EXTENSION <extension name>;'\"

    Note: It is recommended that plpgsql not be removed.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag satisfies: ['SRG-APP-000141-DB-000093']
  tag gid: 'V-VCFI-9X-000032'
  tag rid: 'SV-VCFI-9X-000032'
  tag stig_id: 'VCFI-9X-000032'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  pg_approved_extensions = input('pg_approved_extensions')

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}", "#{input('postgres_db_port')}")

  sql.query('select extname from pg_extension;', ["#{input('postgres_default_db')}"]).output.split.each do |ext|
    describe ext do
      it { should be_in pg_approved_extensions }
    end
  end
end
