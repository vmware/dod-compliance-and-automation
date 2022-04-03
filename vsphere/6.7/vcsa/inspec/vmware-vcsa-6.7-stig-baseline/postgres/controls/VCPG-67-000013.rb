control 'VCPG-67-000013' do
  title 'VMware Postgres must be configured to use TLS.'
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.
Authentication based on user ID and password may be used only when it is not
possible to employ a PKI certificate.

    In such cases, passwords need to be protected at all times, and encryption
is the standard method for protecting passwords during transmission.

    VMware Postgres is configured out of the box to require TLS connections
with remote clients. As an embedded database and available only on localhost
for standalone VCSAs, TLS connections are used only in high-availability
deployments for connections between a primary and a standby. This configuration
must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SHOW ssl;\"|sed
-n 3p|sed -e 's/^[ ]*//'

    Expected result:

    on

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET
ssl TO 'on';\"

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\"
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag satisfies: ['SRG-APP-000172-DB-000075', 'SRG-APP-000442-DB-000379']
  tag gid: 'V-239205'
  tag rid: 'SV-239205r717059_rule'
  tag stig_id: 'VCPG-67-000013'
  tag fix_id: 'F-42397r678987_fix'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = 'SHOW ssl;'

  describe sql.query(sqlquery) do
    its('output') { should cmp "#{input('pg_ssl')}" }
  end
end
