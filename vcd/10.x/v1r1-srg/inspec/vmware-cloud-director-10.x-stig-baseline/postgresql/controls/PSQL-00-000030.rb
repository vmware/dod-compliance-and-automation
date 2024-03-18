control 'PSQL-00-000030' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, etc.) must be restricted to authorized users.'
  desc  "
    If the DBMS were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

    Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

    Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ psql -c \"\\dp *.*\" | grep -E \"information_schema|pg_catalog\"

    If the output from the command produces any results indicating privileges for any user other than postgres, this is a finding.
  "
  desc 'fix', "
    As a database administrator, perform the following at the command prompt:

    $ psql -c \"REVOKE ALL PRIVILEGES ON <name> FROM <user>;\"

    Replace <name> and <user> with the Access Privilege name and account, respectively, discovered during the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag satisfies: ['SRG-APP-000233-DB-000124']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PSQL-00-000030'
  tag cci: ['CCI-001499', 'CCI-001084']
  tag nist: ['CM-5 (6)', 'SC-3']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  pg_superuser = input('postgres_user')

  perm_sql = "SELECT n.nspname, p.oid::regclass::text, pg_catalog.pg_get_userbyid(p.relowner) as Owner, p.relkind, p.relacl
              FROM pg_class p
              JOIN  pg_catalog.pg_namespace n ON n.oid = p.relnamespace
              WHERE relacl is not null
                AND p.relacl not in ('{#{pg_superuser}=arwdDxt/#{pg_superuser},=r/#{pg_superuser}}','{#{pg_superuser}=arwdDxt/#{pg_superuser}}','{=r/#{pg_superuser},#{pg_superuser}=arwdDxt/#{pg_superuser}}')
                AND (CASE WHEN p.oid::regclass::text = 'pg_settings' and p.relacl = '{#{pg_superuser}=arwdDxt/#{pg_superuser},=rw/#{pg_superuser}}' THEN 0 ELSE 1 END) != 0
              ORDER BY 1,2,3,4;"

  db_query = "SELECT datname from pg_database where datname not in ('template0', 'template1');"

  sql.query(db_query, ["#{input('postgres_default_db')}"]).output.split.each do |dbname|
    s = sql.query(perm_sql, ["#{dbname}"]).output
    if s == ''
      describe "DB: #{dbname} - Check Permissions" do
        it 'OK' do
          expect(s).to eq('')
        end
      end
    else
      s.split.each do |info|
        describe "DB: #{dbname} - Check Permissions" do
          it "(ACL: #{info})" do
            expect(info).to eq('')
          end
        end
      end
    end
  end
end
