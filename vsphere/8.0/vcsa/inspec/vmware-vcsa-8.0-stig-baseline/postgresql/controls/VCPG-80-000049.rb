control 'VCPG-80-000049' do
  title 'The vCenter PostgreSQL service must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.'
  desc 'One class of man-in-the-middle, or session hijacking, attack involves the adversary guessing at valid session identifiers based on patterns in identifiers already known.

The preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2 approved random number generator.

However, it is recognized that available database management system (DBMS) products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective.'
  desc 'check', 'At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW ssl;"

If "ssl" is not set to "on", this is a finding.'
  desc 'fix', %q(At the command prompt, run the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET ssl = 'on';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET ssl_cert_file = '/storage/db/vpostgres_ssl/server.crt';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET ssl_key_file = '/storage/db/vpostgres_ssl/server.key';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET ssl_ca_file = '/storage/db/vpostgres_ssl/root_ca.pem';"

Restart the PostgreSQL service by running the following command:

# vmon-cli --restart vmware-vpostgres)
  impact 0.5
  tag check_id: 'C-62918r935436_chk'
  tag severity: 'medium'
  tag gid: 'V-259178'
  tag rid: 'SV-259178r935438_rule'
  tag stig_id: 'VCPG-80-000049'
  tag gtitle: 'SRG-APP-000224-DB-000384'
  tag fix_id: 'F-62827r935437_fix'
  tag satisfies: ['SRG-APP-000224-DB-000384', 'SRG-APP-000441-DB-000378', 'SRG-APP-000442-DB-000379']
  tag cci: ['CCI-001188', 'CCI-002420', 'CCI-002422']
  tag nist: ['SC-23 (3)', 'SC-8 (2)', 'SC-8 (2)']

  ssl_enabled = input('ssl_enabled')
  if ssl_enabled
    sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
    describe sql.query('SHOW ssl;', ["#{input('postgres_default_db')}"]) do
      its('output') { should cmp 'on' }
    end
  else
    describe 'For PostgreSQL installations that are not accessible over the network and do not have SSL turned on, this is Not Applicable.' do
      skip 'For PostgreSQL installations that are not accessible over the network and do not have SSL turned on, this is Not Applicable.'
    end
  end
end
