control "VCPG-67-000002" do
  title "vPostgres database log file data must contain required data elements."
  desc  "Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit records can be generated from various components within the DBMS
(e.g., process, module). Certain specific application functionalities may be
audited as well. The list of audited events is the set of events for which
audits are to be generated. This set of events is typically a subset of the
list of all events for which the system is capable of generating audit records.

    DoD has defined the list of events for which the DBMS will provide an audit
record generation capability as the following:

    (i) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    (ii) Access actions, such as successful and unsuccessful logon attempts,
privileged activities, or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system; and

    (iii) All account creation, modification, disabling, and termination
actions.

    Organizations may define additional events requiring continuous or ad hoc
auditing."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000089-DB-000064"
  tag gid: nil
  tag rid: "VCPG-67-000002"
  tag stig_id: "VCPG-67-000002"
  tag cci: "CCI-000169"
  tag nist: ["AU-12 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep '^\\s*log_line_prefix\\b' /storage/db/vpostgres/postgresql.conf

If \"log_line_prefix\" is not set to \"%m %d %u %r %p %l %c \", this is a
finding:
 "
  desc 'fix', "At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
log_line_prefix TO '%m %d %u %r %p %l %c ';\"

/opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\"
"

  describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
    its('log_line_prefix') { should eq "'%m %d %u %r %p %l %c '" }
  end

end

