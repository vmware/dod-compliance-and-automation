control 'VRPP-8X-000007' do
  title 'VMware Aria Operations vPostgres must generate audit records.'
  desc  "
    Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this.

    This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that vPostgres continually performs to determine if any and every action on the database is permitted.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW pgaudit.log_catalog;\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW pgaudit.log;\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW pgaudit.log_parameter;\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW pgaudit.log_statement_once;\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW pgaudit.log_level;\\\"\"

    If \"pgaudit.log_catalog\" is not set to \"on\", this is a finding.

    If \"pgaudit.log\" is not set to \"ddl, role\", this is a finding.

    If \"pgaudit.log_parameter\" is not set to \"on\", this is a finding.

    If \"pgaudit.log_statement_once\" is not set to \"off\", this is a finding.

    If \"pgaudit.log_level\" is not set to \"log\", this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt for each finding:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -c \\\"ALTER SYSTEM SET pgaudit.log_catalog = 'on';\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -c \\\"ALTER SYSTEM SET pgaudit.log = 'ddl, role';\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -c \\\"ALTER SYSTEM SET pgaudit.log_parameter = 'on';\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -c \\\"ALTER SYSTEM SET pgaudit.log_statement_once = 'off';\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -c \\\"ALTER SYSTEM SET pgaudit.log_level = 'log';\\\"\"

    Reload the vPostgres service by running the following command:

    # systemctl restart vpostgres-repl.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag satisfies: ['SRG-APP-000091-DB-000325', 'SRG-APP-000092-DB-000208', 'SRG-APP-000492-DB-000332', 'SRG-APP-000492-DB-000333', 'SRG-APP-000495-DB-000326', 'SRG-APP-000495-DB-000327', 'SRG-APP-000495-DB-000328', 'SRG-APP-000495-DB-000329', 'SRG-APP-000496-DB-000334', 'SRG-APP-000496-DB-000335', 'SRG-APP-000499-DB-000330', 'SRG-APP-000499-DB-000331', 'SRG-APP-000501-DB-000336', 'SRG-APP-000501-DB-000337', 'SRG-APP-000504-DB-000354', 'SRG-APP-000504-DB-000355', 'SRG-APP-000507-DB-000356', 'SRG-APP-000507-DB-000357']
  tag gid: 'V-VRPP-8X-000007'
  tag rid: 'SV-VRPP-8X-000007'
  tag stig_id: 'VRPP-8X-000007'
  tag cci: ['CCI-000172', 'CCI-001464']
  tag nist: ['AU-12 c', 'AU-14 (1)']

  describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW pgaudit.log_catalog;\"'") do
    its('stdout.strip') { should cmp 'on' }
  end
  describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW pgaudit.log;\"'") do
    its('stdout.strip') { should cmp 'ddl, role' }
  end
  describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW pgaudit.log_parameter;\"'") do
    its('stdout.strip') { should cmp 'on' }
  end
  describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW pgaudit.log_statement_once;\"'") do
    its('stdout.strip') { should cmp 'off' }
  end
  describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW pgaudit.log_level;\"'") do
    its('stdout.strip') { should cmp 'log' }
  end
end
