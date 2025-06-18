control 'VCFC-9X-000035' do
  title 'The VMware Cloud Foundation SDDC Manager PostgreSQL service must be configured to use an authorized port.'
  desc  "
    In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

    Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

    To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

    Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ /usr/pgsql/15/bin/psql -h localhost -U postgres -A -t -c \"SHOW port;\"

    Example result:

    5432

    If the \"port\" setting is not configured to \"5432\", this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # /usr/pgsql/15/bin/psql -h localhost -U postgres -c \"ALTER SYSTEM SET port = '5432';\"

    Reload the PostgreSQL service by running the following command:

    # systemctl restart postgres
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag satisfies: ['SRG-APP-000383-DB-000364']
  tag gid: 'V-VCFC-9X-000035'
  tag rid: 'SV-VCFC-9X-000035'
  tag stig_id: 'VCFC-9X-000035'
  tag cci: ['CCI-000382', 'CCI-001762']
  tag nist: ['CM-7 (1) (b)', 'CM-7 b']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW port;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp '5432' }
  end
end
