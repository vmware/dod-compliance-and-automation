control "VCPG-67-000027" do
  title "The vPostgres database must set log_disconnections to on."
  desc  "For completeness of forensic analysis, it is necessary to know how
long a user's (or other principal's) connection to the DBMS lasts. This can be
achieved by recording disconnections, in addition to logons/connections, in the
audit logs.

    Disconnection may be initiated by the user or forced by the system (as in a
timeout) or result from a system or network failure. To the greatest extent
possible, all disconnections must be logged."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000505-DB-000352"
  tag gid: nil
  tag rid: "VCPG-67-000027"
  tag stig_id: "VCPG-67-000027"
  tag cci: "CCI-000172"
  tag nist: ["AU-12 c", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep '^log_disconnections' /storage/db/vpostgres/postgresql.conf

If log_disconnections is not on, this is a finding."
  desc 'fix', "At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
log_disconnections TO 'on';\"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\""

  describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
    its('log_disconnections') { should cmp "on" }
  end

end

