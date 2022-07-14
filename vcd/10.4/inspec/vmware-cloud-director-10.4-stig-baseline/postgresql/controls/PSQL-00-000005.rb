control 'PSQL-00-000005' do
  title 'PostgreSQL must enable pgaudit to provide audit record generation capabilities.'
  desc  "
    Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the DBMS (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

    DoD has defined the list of events for which the DBMS will provide an audit record generation capability as the following:

    (i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

    (ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

    (iii) All account creation, modification, disabling, and termination actions.

    Organizations may define additional events requiring continuous or ad hoc auditing.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ psql -A -t -c \"SHOW shared_preload_libraries\"

    Example result:

    pgaudit

    If the output from the command does not include pgaudit, this is a finding.
  "
  desc 'fix', "
    Instructions to install pgaudit can be referenced online and vary by Linux distribution.

    Edit the postgresql.conf file for your installation and update the following options:

    shared_preload_libraries = 'pgaudit'

    Note: This can be a comma-separated list if more than one library needs to be loaded.

    Reload the PostgreSQL service by running the following command:

    # systemctl reload postgresql

    or

    # service postgresql reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PSQL-00-000005'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  describe sql.query('SHOW shared_preload_libraries;', ["#{input('postgres_default_db')}"]) do
    its('output') { should match /pgaudit/ }
  end
end
