control "VCPG-67-000001" do
  title "vPostgres must limit the number of connections."
  desc  "Database management includes the ability to control the number of
users and user sessions utilizing a DBMS. Unlimited concurrent connections to
the DBMS could allow a successful Denial of Service (DoS) attack by exhausting
connection resources; and a system can also fail or be degraded by an overload
of legitimate users. Limiting the number of concurrent sessions per user is
helpful in reducing these risks.

    This requirement addresses concurrent session control for a single account.
It does not address concurrent sessions by a single user via multiple system
accounts; and it does not deal with the total number of sessions across all
accounts.

    The capability to limit the number of concurrent sessions per user must be
configured in or added to the DBMS (for example, by use of a logon trigger),
when this is technically feasible. Note that it is not sufficient to limit
sessions via a web server or application server alone, because legitimate users
and adversaries can potentially connect to the DBMS by other means.

    The organization will need to define the maximum number of concurrent
sessions by account type, by account, or a combination thereof. In deciding on
the appropriate number, it is important to consider the work requirements of
the various types of users. For example, 2 might be an acceptable limit for
general users accessing the database via an application; but 10 might be too
few for a database administrator using a database management GUI tool, where
each query tab and navigation pane may count as a separate session.

    (Sessions may also be referred to as connections or logons, which for the
purposes of this requirement are synonyms.)"
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000001-DB-000031"
  tag gid: nil
  tag rid: "VCPG-67-000001"
  tag stig_id: "VCPG-67-000001"
  tag cci: "CCI-000054"
  tag nist: ["AC-10", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep '^\\s*max_connections\\b' /storage/db/vpostgres/postgresql.conf

If \"max_connections\" is not \"100\", this is a finding."
  desc 'fix', "At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
max_connections TO '100';\"

/opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\""

  #describe postgres_conf("#{input('postgres_conf_path')}") do
  describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
    its('max_connections') { should eq "100" }
  end

end

