control "VCPG-67-000016" do
  title "The vPostgres database must complete writing log entries prior to
returning results."
  desc  "Failure to a known state can address safety or security in accordance
with the mission/business needs of the organization.

    Failure to a known secure state helps prevent a loss of confidentiality,
integrity, or availability in the event of a failure of the information system
or a component of the system.

    Preserving information system state information helps to facilitate system
restart and return to the operational mode of the organization with less
disruption of mission/business processes.

    Since it is usually not possible to test this capability in a production
environment, systems should either be validated in a testing environment or
prior to installation. This requirement is usually a function of the design of
the IDPS component. Compliance can be verified by acceptance/validation
processes or vendor attestation."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000226-DB-000147"
  tag gid: nil
  tag rid: "VCPG-67-000016"
  tag stig_id: "VCPG-67-000016"
  tag cci: "CCI-001665"
  tag nist: ["SC-24", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT name,setting
FROM pg_settings WHERE name IN
('fsync','full_page_writes','synchronous_commit');\"

If \"fsync\", \"full_page_writes\", and \"synchronous_commit\" are not all
\"on\", this is a finding.

The command should return the below output
        name        | setting
--------------------+---------
 fsync              | on
 full_page_writes   | on
 synchronous_commit | on
(3 rows)"
  desc 'fix', "At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
<name> TO 'on';\"

/opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\"

Note: Substitute <name> with the incorrectly set parameter
"

  describe postgres_session('postgres','','localhost').query("SELECT name,setting FROM pg_settings WHERE name IN ('fsync','full_page_writes','synchronous_commit');") do
    its('output.strip') { should match /^fsync\|on$/ }
    its('output.strip') { should match /^full_page_writes\|on$/ }
    its('output.strip') { should match /^synchronous_commit\|on$/ }
  end

end

