control 'VRPP-8X-000001' do
  title 'VMware Aria Operations vPostgres must limit the number of concurrent sessions.'
  desc  "
    Database management includes the ability to control the number of users and user sessions utilizing it. Unlimited concurrent connections to vPostgres could allow a successful Denial of Service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

    This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts.

    (Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.)
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, run the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \\\"SHOW max_connections;\\\"\"

    Example result:

    200

    If \"max_connections\" is set to -1 or more connections are configured than documented, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -p 5433 -c \\\"ALTER SYSTEM SET max_connections TO 200;\\\"\"

    Reload the vPostgres service by running the following command:

    # systemctl restart vpostgres-repl.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag gid: 'V-VRPP-8X-000001'
  tag rid: 'SV-VRPP-8X-000001'
  tag stig_id: 'VRPP-8X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW max_connections;\"'") do
    its('stdout.strip') { should_not cmp '-1' }
    its('stdout.strip') { should_not cmp '' }
  end
end
