control "VCPG-67-000026" do
  title "The vPostgres database must set log_connections to on."
  desc  "For completeness of forensic analysis, it is necessary to track
who/what (a user or other principal) logs on to the DBMS."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000503-DB-000350"
  tag gid: nil
  tag rid: "VCPG-67-000026"
  tag stig_id: "VCPG-67-000026"
  tag cci: "CCI-000172"
  tag nist: ["AU-12 c", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep '^log_connections' /storage/db/vpostgres/postgresql.conf

If log_connections is not on, this is a finding."
  desc 'fix', "At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
log_connections TO 'on';\"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\""

  describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
    its('log_connections') { should cmp "on" }
  end

end

