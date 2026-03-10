control 'PSQL-00-000032' do
  title 'The Cloud Director PostgreSQL database must not load unused database components, software, and database objects.'
  desc  "
    Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

    It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.

    DBMSs must adhere to the principles of least functionality by providing only essential capabilities.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -c \\\"select * from pg_extension where extname != 'plpgsql';\\\"\"

    If any extensions exist that are not approved, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    $ su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -c \\\"DROP EXTENSION <extension name>;\\\"\"

    Note: It is recommended that plpgsql not be removed.
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

  sql_result = command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"select extname from pg_extension;\"'")

  sql_result.stdout.split.each do |ext|
    describe ext do
      it { should be_in pg_approved_extensions }
    end
  end
end
