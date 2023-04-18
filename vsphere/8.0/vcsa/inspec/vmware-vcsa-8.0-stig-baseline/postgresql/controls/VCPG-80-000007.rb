control 'VCPG-80-000007' do
  title 'The vCenter PostgreSQL service must generate audit records.'
  desc  "
    Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. Database management systems (DBMS) typically make such information available through views or functions.

    This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that PostgreSQL continually performs to determine if any and every action on the database is permitted.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW pgaudit.log_catalog;\"
    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW pgaudit.log;\"
    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW pgaudit.log_parameter;\"
    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW pgaudit.log_statement_once;\"
    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW pgaudit.log_level;\"

    If \"pgaudit.log_catalog\" is not set to \"on\", this is a finding.

    If \"pgaudit.log\" is not set to \"all, -misc\", this is a finding.

    If \"pgaudit.log_parameter\" is not set to \"on\", this is a finding.

    If \"pgaudit.log_statement_once\" is not set to \"off\", this is a finding.

    If \"pgaudit.log_level\" is not set to \"log\", this is a finding.
  "
  desc 'fix', "
    A script is included with vCenter to generate a PostgreSQL STIG configuration.

    At the command prompt, run the following commands:

    # chmod +x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py
    # /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py --action stig_enable --pg-data-dir /storage/db/vpostgres
    # chmod -x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py

    Restart the PostgreSQL service by running the following command:

    # vmon-cli --restart vmware-vpostgres
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag satisfies: ['SRG-APP-000091-DB-000325', 'SRG-APP-000492-DB-000332', 'SRG-APP-000492-DB-000333', 'SRG-APP-000495-DB-000326', 'SRG-APP-000495-DB-000327', 'SRG-APP-000495-DB-000328', 'SRG-APP-000495-DB-000329', 'SRG-APP-000496-DB-000334', 'SRG-APP-000496-DB-000335', 'SRG-APP-000499-DB-000330', 'SRG-APP-000499-DB-000331', 'SRG-APP-000501-DB-000336', 'SRG-APP-000501-DB-000337', 'SRG-APP-000504-DB-000354', 'SRG-APP-000504-DB-000355', 'SRG-APP-000507-DB-000356', 'SRG-APP-000507-DB-000357']
  tag gid: 'V-VCPG-80-000007'
  tag rid: 'SV-VCPG-80-000007'
  tag stig_id: 'VCPG-80-000007'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW pgaudit.log_catalog;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'on' }
  end
  describe sql.query('SHOW pgaudit.log;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'all, -misc' }
  end
  describe sql.query('SHOW pgaudit.log_parameter', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'on' }
  end
  describe sql.query('SHOW pgaudit.log_statement_once', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'off' }
  end
  describe sql.query('SHOW pgaudit.log_level', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'log' }
  end
end
