control 'VCFL-9X-000005' do
  title 'The VMware Cloud Foundation vCenter PostgreSQL service must enable "pgaudit" to provide audit record generation capabilities.'
  desc  "
    Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the DBMS (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

    DOD has defined the list of events for which the DBMS will provide an audit record generation capability as the following:

    (i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

    (ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

    (iii) All account creation, modification, disabling, and termination actions.

    Organizations may define additional events requiring continuous or ad hoc auditing.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c \"SHOW shared_preload_libraries;\"

    Example result:

    health_status_worker,pg_stat_statements,pgaudit

    If the \"shared_preload_libraries\" setting does not include \"pgaudit\", this is a finding.
  "
  desc 'fix', "
    A script is included with vCenter to generate a PostgreSQL STIG configuration.

    As a database administrator, perform the following at the command prompt:

    # chmod +x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py
    # /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py --action stig_enable --pg-data-dir /storage/db/vpostgres
    # chmod -x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py

    Restart the PostgreSQL service by running the following command:

    # vmon-cli --restart vmware-vpostgres
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag gid: 'V-VCFL-9X-000005'
  tag rid: 'SV-VCFL-9X-000005'
  tag stig_id: 'VCFL-9X-000005'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  describe sql.query('SHOW shared_preload_libraries;', ["#{input('postgres_default_db')}"]) do
    its('output') { should match /pgaudit/ }
  end
end
