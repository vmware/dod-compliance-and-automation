control 'VCFI-9X-000007' do
  title 'The VMware Cloud Foundation Operations PostgreSQL service must generate audit records.'
  desc  "
    Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

    This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that the PostgreSQL continually performs to determine if any and every action on the database is permitted.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c 'SHOW pgaudit.log;'\"

    If the \"pgaudit.log\" setting is not configured to \"all, -misc, -read\", this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"ALTER SYSTEM SET pgaudit.log = 'all, -misc, -read';\\\"\"

    Reload the PostgreSQL service by running the following command:

    # systemctl restart vpostgres-repl.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag satisfies: ['SRG-APP-000091-DB-000325', 'SRG-APP-000381-DB-000361', 'SRG-APP-000492-DB-000332', 'SRG-APP-000492-DB-000333', 'SRG-APP-000495-DB-000326', 'SRG-APP-000495-DB-000327', 'SRG-APP-000495-DB-000328', 'SRG-APP-000495-DB-000329', 'SRG-APP-000496-DB-000334', 'SRG-APP-000496-DB-000335', 'SRG-APP-000499-DB-000330', 'SRG-APP-000499-DB-000331', 'SRG-APP-000501-DB-000336', 'SRG-APP-000501-DB-000337', 'SRG-APP-000504-DB-000354', 'SRG-APP-000504-DB-000355', 'SRG-APP-000507-DB-000356', 'SRG-APP-000507-DB-000357']
  tag gid: 'V-VCFI-9X-000007'
  tag rid: 'SV-VCFI-9X-000007'
  tag stig_id: 'VCFI-9X-000007'
  tag cci: ['CCI-000172', 'CCI-003938']
  tag nist: ['AU-12 c', 'CM-5 (1) (b)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}", "#{input('postgres_db_port')}")

  describe sql.query('SHOW pgaudit.log;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'all, -misc, -read' }
  end
end
