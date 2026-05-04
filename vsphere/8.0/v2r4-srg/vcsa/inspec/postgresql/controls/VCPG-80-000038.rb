control 'VCPG-80-000038' do
  title 'The vCenter PostgreSQL service must encrypt passwords for user authentication.'
  desc 'The DOD standard for authentication is DOD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate and requires AO approval.

In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the database management system (DBMS).'
  desc 'check', 'At the command prompt, run the following command:

$ /opt/vmware/vpostgres/current/bin/psql -U postgres -A -t -c "SHOW password_encryption;"

Expected result:

scram-sha-256

If the output does not match the expected result, this is a finding.

Note: Prior to Update 2, "md5" is the expected result.'
  desc 'fix', 'A script is included with vCenter to generate a PostgreSQL STIG configuration.

At the command prompt, run the following commands:

# chmod +x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py
# /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py --action stig_enable --pg-data-dir /storage/db/vpostgres
# chmod -x /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py

Restart the PostgreSQL service by running the following command:

# vmon-cli --restart vmware-vpostgres'
  impact 0.7
  tag check_id: 'C-62916r935430_chk'
  tag severity: 'high'
  tag gid: 'V-259176'
  tag rid: 'SV-259176r1003664_rule'
  tag stig_id: 'VCPG-80-000038'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-62825r935431_fix'
  tag cci: ['CCI-004062']
  tag nist: ['IA-5 (1) (d)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")

  describe sql.query('SHOW password_encryption;', ["#{input('postgres_default_db')}"]) do
    its('output') { should cmp 'scram-sha-256' }
  end
end
