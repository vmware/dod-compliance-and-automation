control "VCPG-67-000024" do
  title "vPostgres database must be configured to validate characer encoding to
UTF-8."
  desc  "A common vulnerability is unplanned behavior when invalid inputs are
received. This requirement guards against adverse or unintended system behavior
caused by invalid inputs, where information system responses to the invalid
input may be disruptive or cause the system to fail into an unsafe state.

    The behavior will be derived from the organizational and system
requirements and includes, but is not limited to, notification of the
appropriate personnel, creating an audit record, and rejecting invalid input."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000447-DB-000393"
  tag gid: nil
  tag rid: "VCPG-67-000024"
  tag stig_id: "VCPG-67-000024"
  tag cci: "CCI-002754"
  tag nist: ["SI-10 (3)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep '^\\s*client_encoding\\b' /storage/db/vpostgres/postgresql.conf

If \"client_encoding\" is not \"UTF8\", this is a finding.
 "
  desc 'fix', "At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
client_encoding TO 'UTF8';\"

/opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\""

  describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
    its('client_encoding') { should cmp "UTF8" }
  end

end

