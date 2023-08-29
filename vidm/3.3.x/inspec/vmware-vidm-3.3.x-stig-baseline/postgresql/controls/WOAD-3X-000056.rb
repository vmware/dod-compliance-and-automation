control 'WOAD-3X-000056' do
  title 'The Workspace ONE Access vPostgres instance must not allow schema access to unauthorized accounts.'
  desc  "
    Database Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality.

    VMware Postgres contains a number of system configuration schema whose access must be strictly limited. By default, the pg_catalog and information_schema objects are configured to only be accessible in a read-only manner publicly and otherwise only accessible by the postgres user. This configuration must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"\\dp .*.;\"/opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"\\dp .*.;\"|grep -E \"information_schema|pg_catalog\"|awk -F '|' '{print $4}'|awk -F '/' '{print $1}'|grep -v \"=r\"|grep -v \"postgres\"|grep -v \"  \"

    If any lines are returned, this is a finding.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"REVOKE ALL PRIVILEGES ON <name> FROM <user>;\"

    Replace <name> and <user> with the Access Privilege name and account, respectively, discovered during the check.

    Note: For a non-clustered vRSLCM deployed instance you may be prompted for the postgres users password which is available at /usr/local/horizon/conf/db.pwd.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag gid: 'V-WOAD-3X-000056'
  tag rid: 'SV-WOAD-3X-000056'
  tag stig_id: 'WOAD-3X-000056'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  clustered = input('clustered')

  if clustered
    describe command("/opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"\\dp .*.;\"/opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"\\dp .*.;\"|grep -E \"information_schema|pg_catalog\"|awk -F '|' '{print $4}'|awk -F '/' '{print $1}'|grep -v \"=r\"|grep -v \"postgres\"|grep -v \"  \"") do
      its('stdout.strip') { should cmp '' }
    end
  else
    # sqlpw = file("#{input('postgres_pw_file')}").content.strip
    # describe command("PGPASSWORD=#{sqlpw} /opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"\\dp .*.;\"/opt/vmware/vpostgres/9.6/bin/psql -U postgres -c \"\\dp .*.;\"|grep -E \"information_schema|pg_catalog\"|awk -F '|' '{print $4}'|awk -F '/' '{print $1}'|grep -v \"=r\"|grep -v \"postgres\"|grep -v \"  \"") do
    # its('stdout.strip') { should cmp "" }
    # end
    describe 'Not a finding by default' do
      skip 'Manual check until better way of protecting password is found but control is not a finding by default.'
    end
  end
end
