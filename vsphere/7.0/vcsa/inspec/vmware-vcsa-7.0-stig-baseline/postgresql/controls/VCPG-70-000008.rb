control 'VCPG-70-000008' do
  title 'VMware Postgres must be configured to use the correct port.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports, protocols, and services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.

'
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW port;"

Expected result:

5432

If the output does not match the expected result, this is a finding.'
  desc 'fix', %q(At the command prompt, run the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET port TO '5432';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  tag check_id: 'C-60273r887578_chk'
  tag severity: 'medium'
  tag gid: 'V-256598'
  tag rid: 'SV-256598r887580_rule'
  tag stig_id: 'VCPG-70-000008'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-60216r887579_fix'
  tag satisfies: ['SRG-APP-000142-DB-000094', 'SRG-APP-000383-DB-000364']
  tag cci: ['CCI-000382', 'CCI-001762']
  tag nist: ['CM-7 b', 'CM-7 (1) (b)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW port;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_port')}" }
  end
end
