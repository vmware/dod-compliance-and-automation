control 'WOAD-3X-000037' do
  title 'The Workspace ONE Access vPostgres instance must be configured to use the correct port.'
  desc  "
    In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

    Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

    To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

    Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c \"SHOW port;\"

    Expected result:

    5432

    If the output does not match the expected result, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"ALTER SYSTEM SET port TO '5432';\"

    # systemctl restart vpostgres.service

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag satisfies: ['SRG-APP-000383-DB-000364']
  tag gid: 'V-WOAD-3X-000037'
  tag rid: 'SV-WOAD-3X-000037'
  tag stig_id: 'WOAD-3X-000037'
  tag cci: ['CCI-000382', 'CCI-001762']
  tag nist: ['CM-7 (1) (b)', 'CM-7 b']

  clustered = input('clustered')

  if clustered
    describe command('/opt/vmware/vpostgres/9.6/bin/psql -U postgres -A -t -c "SHOW port;"') do
      its('stdout.strip') { should cmp '5432' }
    end
  else
    sqlpw = file("#{input('postgres_pw_file')}").content.strip
    sql = postgres_session("#{input('postgres_user')}", sqlpw, "#{input('postgres_host')}")
    sqlquery = 'SHOW port;'

    describe sql.query(sqlquery) do
      its('output') { should cmp '5432' }
    end
  end
end
