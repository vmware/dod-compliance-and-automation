control 'VCPG-70-000007' do
  title 'VMware Postgres must limit modify privileges to authorized accounts.'
  desc  "
    If VMware Postgres were to allow any user to make changes to database structure or logic, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

    Only qualified and authorized individuals must be allowed to obtain access to information system components to initiate changes, including upgrades and modifications.

    Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"\\du;\"|grep \"Create\"

    Expected result:

     postgres   | Superuser, Create role, Create DB, Replication, Bypass RLS | {}
     vc         | Create DB                                                  | {}
     vlcmuser   | Create DB                                                  | {}

    If the accounts other than \"postgres\",\"vc\", and \"vlcmuser\" have any \"Create\" privileges, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"REVOKE ALL PRIVILEGES FROM <user>;\"

    Replace <user> with the account discovered during the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag gid: 'V-256597'
  tag rid: 'SV-256597r887577_rule'
  tag stig_id: 'VCPG-70-000007'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  list = ['postgres', 'vc', 'vlcmuser']
  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sqlquery = "SELECT usename FROM pg_catalog.pg_user WHERE usecreatedb = 't';"

  result = sql.query(sqlquery)
  users = result.lines

  users.each do |user|
    describe user do
      it { should be_in list }
    end
  end
end
