control 'VRPP-8X-000049' do
  title 'The DBMS must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.'
  desc  "
    One class of man-in-the-middle, or session hijacking, attack involves the adversary guessing at valid session identifiers based on patterns in identifiers already known.

    The preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2 approved random number generator.

    However, it is recognized that available DBMS products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective.
  "
  desc  'rationale', ''
  desc  'check', "
    For PostgreSQL installations that are not accessible over the network, this control is Not Applicable.

    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -A -t -c \\\"SHOW ssl;\\\"\"

    If \"ssl\" is not set to \"on\", this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -c \\\"ALTER SYSTEM SET ssl = 'on';\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -c \\\"ALTER SYSTEM SET ssl_cert_file = '/path/to/server.crt';\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -c \\\"ALTER SYSTEM SET ssl_key_file = '/path/to/server.key';\\\"\"
    # su - postgres -c \"/opt/vmware/vpostgres/current/bin/psql -c \\\"ALTER SYSTEM SET ssl_ca_file = '/path/to/ca.crt';\\\"\"

    Reload the PostgreSQL service by running the following command:

    # systemctl restart vpostgres.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000224-DB-000384'
  tag satisfies: %w[SRG-APP-000441-DB-000378 SRG-APP-000442-DB-000379]
  tag gid: 'V-VRPP-8X-000049'
  tag rid: 'SV-VRPP-8X-000049'
  tag stig_id: 'VRPP-8X-000049'
  tag cci: %w[CCI-001188 CCI-002420 CCI-002422]
  tag nist: ['SC-23 (3)', 'SC-8 (2)']

  ssl_enabled = input('ssl_enabled')
  if ssl_enabled
    describe command("su - postgres -c '/opt/vmware/vpostgres/current/bin/psql -A -t -c \"SHOW ssl;\"'") do
      its('stdout.strip') { should cmp 'on' }
    end
  else
    describe 'For PostgreSQL installations that are not accessible over the network and do not have SSL turned on, this is Not Applicable.' do
      skip 'For PostgreSQL installations that are not accessible over the network and do not have SSL turned on, this is Not Applicable.'
    end
  end
end
