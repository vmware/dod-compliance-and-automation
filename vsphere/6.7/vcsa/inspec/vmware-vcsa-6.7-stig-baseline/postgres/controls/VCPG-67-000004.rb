control "VCPG-67-000004" do
  title "vPostgres database must have log_truncate_on_rotation enabled."
  desc  "It is critical that when the DBMS is at risk of failing to process
audit logs as required, it take action to mitigate the failure. Audit
processing failures include: software/hardware errors; failures in the audit
capturing mechanisms; and audit storage capacity being reached or exceeded.
Responses to audit failure depend upon the nature of the failure mode.

    When availability is an overriding concern, approved actions in response to
an audit failure are as follows:

    (i) If the failure was caused by the lack of audit record storage capacity,
the DBMS must continue generating audit records, if possible (automatically
restarting the audit service if necessary), overwriting the oldest audit
records in a first-in-first-out manner.

    (ii) If audit records are sent to a centralized collection server and
communication with this server is lost or the server fails, the DBMS must queue
audit records locally until communication is restored or until the audit
records are retrieved manually. Upon restoration of the connection to the
centralized collection server, action should be taken to synchronize the local
audit data with the collection server.

    Systems where availability is paramount will most likely be MAC I; the
final determination is the prerogative of the application owner, subject to
Authorizing Official concurrence. In any case, sufficient auditing resources
must be allocated to avoid audit data loss in all but the most extreme
situations."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000109-DB-000321"
  tag gid: nil
  tag rid: "VCPG-67-000004"
  tag stig_id: "VCPG-67-000004"
  tag cci: "CCI-000140"
  tag nist: ["AU-5 b", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep '^\\s*log_truncate_on_rotation\\b' /storage/db/vpostgres/postgresql.conf

If \"log_truncate_on_rotation\" is not set to \"on\", this is a finding."
  desc 'fix', "At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
log_truncate_on_rotation TO 'on';\"

/opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\""

  describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
    its('log_truncate_on_rotation') { should eq "on" }
  end

end

