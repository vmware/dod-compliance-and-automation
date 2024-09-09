control 'VRPP-8X-000005' do
  title 'VMware Aria Operations vPostgres must enable pgaudit to provide audit record generation capabilities.'
  desc  "
    Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within vPostgres (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

    DoD has defined the list of events for which the database will provide an audit record generation capability as the following:

    (i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

    (ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

    (iii) All account creation, modification, disabling, and termination actions.

    Organizations may define additional events requiring continuous or ad hoc auditing.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, run the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW shared_preload_libraries;\\\"\"

    Example result:

    pgaudit

    If the output from the command does not include 'pgaudit', this is a finding.
  "
  desc 'fix', "
    Find the postgresql.conf file path by running the following command:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -c \\\"SHOW config_file;\\\"\"

    Edit the postgresql.conf file for your installation and add or update the following line to include 'pgaudit':

    shared_preload_libraries = 'pgaudit'

    Note: This can be a comma-separated list if more than one library needs to be loaded.

    Reload the vPostgres service by running the following command:

    # systemctl restart vpostgres-repl.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag gid: 'V-VRPP-8X-000005'
  tag rid: 'SV-VRPP-8X-000005'
  tag stig_id: 'VRPP-8X-000005'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW shared_preload_libraries;\"'") do
    its('stdout.strip') { should match /pgaudit/ }
  end
end
