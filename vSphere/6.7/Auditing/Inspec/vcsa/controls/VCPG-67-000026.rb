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
  tag fix_id: nil
  tag cci: "CCI-000172"
  tag nist: ["AU-12 c", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AU-12 c"
  tag check: "At the command prompt, execute the following command:

# grep '^log_connections' /storage/db/vpostgres/postgresql.conf

If log_connections is not on, this is a finding."
  tag fix: "At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
log_connections TO 'on';\"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\""

  describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
    its('log_connections') { should cmp "on" }
  end

end

