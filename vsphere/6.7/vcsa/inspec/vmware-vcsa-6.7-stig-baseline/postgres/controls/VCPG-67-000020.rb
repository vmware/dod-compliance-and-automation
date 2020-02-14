control "VCPG-67-000020" do
  title "The vPostgres database must have log collection enabled."
  desc  "Without the ability to centrally manage the content captured in the
audit records, identification, troubleshooting, and correlation of suspicious
behavior would be difficult and could lead to a delayed or incomplete analysis
of an ongoing attack.

    The content captured in audit records must be managed from a central
location (necessitating automation). Centralized management of audit records
and logs provides for efficiency in maintenance and management of records, as
well as the backup and archiving of those records.

    The DBMS may write audit records to database tables, to files in the file
system, to other kinds of local repository, or directly to a centralized log
management system. Whatever the method used, it must be compatible with
off-loading the records to the centralized system."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000356-DB-000314"
  tag gid: nil
  tag rid: "VCPG-67-000020"
  tag stig_id: "VCPG-67-000020"
  tag cci: "CCI-001844"
  tag nist: ["AU-3 (2)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep '^\\s*logging_collector\\b' /storage/db/vpostgres/postgresql.conf

If \"logging_collector\" is not \"on\", this is a finding."
  desc 'fix', "At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
logging_collector TO 'on';\"

/opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\""

  describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
    its('logging_collector') { should cmp "on" }
  end

end

