control "VCPG-67-000021" do
  title "The vPostgres database must be configured to log to stderr."
  desc  "In order for vPostgres logs to be successfully sent to a remote log
management system, the vPostgres deployment must log events to stderr. Those
events will be caputred and logged to disk where they will be picked up by
rsyslog for shipping."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000359-DB-000319"
  tag gid: nil
  tag rid: "VCPG-67-000021"
  tag stig_id: "VCPG-67-000021"
  tag cci: "CCI-001855"
  tag nist: ["AU-5 (1)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep \"^log_destination\"  /storage/db/vpostgres/postgresql.conf

If 'log_destination' is not set to at least 'stderr', this is a finding.

If there is no output, vPostgres will default to \"stderr\", this is not a
finding."
  desc 'fix', "Navigate to and open /storage/db/vpostgres/postgresql.conf.

Find and replace 'log_destination', if it exists, with the below configuration:

log_destination = 'stderr'"

  describe.one do
    describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
      its('log_destination') { should cmp nil }
    end
    describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
      its('log_destination') { should cmp "stderr" }
    end
  end

end

