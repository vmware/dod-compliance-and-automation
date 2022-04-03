control 'VCPG-67-000011' do
  title 'VMware Postgres must be configured to use the correct port.'
  desc  "To prevent unauthorized connection of devices, unauthorized transfer
of information, or unauthorized tunneling (i.e., embedding of data types within
data types), organizations must disable or restrict unused or unnecessary
physical and logical ports/protocols/services on information systems.

    Applications are capable of providing a wide variety of functions and
services. Some of the functions and services provided by default may not be
necessary to support essential organizational operations. Additionally, it is
sometimes convenient to provide multiple services from a single component
(e.g., email and web services); however, doing so increases risk over limiting
the services provided by any one component.

    To support the requirements and principles of least functionality, the
application must support the organizational requirements, providing only
essential capabilities and limiting the use of ports, protocols, and/or
services to only those required, authorized, and approved to conduct official
business or to address authorized quality-of-life issues.

    Database management systems using ports, protocols, and services deemed
unsafe are open to attack through those ports, protocols, and services. This
can allow unauthorized access to the database and through the database to other
components of the information system.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SHOW port;\"|sed
-n 3p|sed -e 's/^[ ]*//'

    Expected result:

    5432

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
port TO '5432';\"

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag satisfies: ['SRG-APP-000142-DB-000094', 'SRG-APP-000383-DB-000364']
  tag gid: 'V-239203'
  tag rid: 'SV-239203r678982_rule'
  tag stig_id: 'VCPG-67-000011'
  tag fix_id: 'F-42395r678981_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW port;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_port')}" }
  end
end
