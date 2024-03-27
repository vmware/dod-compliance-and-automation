control 'PSQL-00-000029' do
  title 'PostgreSQL objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers) must be owned by principals authorized for ownership.'
  desc  "
    Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

    Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed.
  "
  desc  'rationale', ''
  desc  'check', "
    As a database administrator, perform the following at the command prompt:

    $ psql -x -c \"\\dn *.*\"
    $ psql -x -c \"\\dt *.*\"
    $ psql -x -c \"\\ds *.*\"
    $ psql -x -c \"\\dv *.*\"
    $ psql -x -c \"\\df+ *.*\"

    If any object is not owned by an authorized role for ownership, this is a finding.
  "
  desc 'fix', "
    Assign ownership of authorized objects to authorized object owner accounts.

    For example, to update the other on a database.

    As a database administrator, perform the following at the command prompt:

    $ psql -c \"ALTER TABLE <tablename> OWNER TO <ownername>;\"

    Replace <tablename> with the name of the table discovered during the check and <ownername> with the appropriate owner name from the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PSQL-00-000029'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  sql = postgres_session("#{input('postgres_user')}", "#{input('postgres_pass')}", "#{input('postgres_host')}")
  sql_owners = input('allowed_object_owners')
  # Get SQL version since some checks do not work on 10
  sqlversion = sql.query('SHOW server_version;', ["#{input('postgres_default_db')}"]).output

  base_sql     = "SELECT distinct pg_catalog.pg_get_userbyid(c.relowner) as Owner
                  FROM pg_catalog.pg_class c
                  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  WHERE c.relkind = '%s'
                  ORDER BY 1;"

  schema_sql   = "SELECT distinct u.usename as Owner
                  FROM pg_catalog.pg_namespace s
                  JOIN pg_catalog.pg_user u on u.usesysid = s.nspowner
                  ORDER BY 1;"

  # f for a normal function, p for a procedure, a for an aggregate function, or w for a window function
  function_sql = "SELECT distinct pg_catalog.pg_get_userbyid(p.proowner) as Owner
                  FROM   pg_catalog.pg_proc p
                  JOIN  pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                  WHERE p.prokind in (%s)
                  ORDER BY 1;"

  db_query = "SELECT datname from pg_database where datname not in ('postgres', 'template0', 'template1');"

  # Check postgres DB for any objects not owned by postgres user
  dbname = 'postgres'

  sql.query(schema_sql, ["#{dbname}"]).output.split.each do |info|
    describe "DB: #{dbname} - Schema" do
      it "Owner: #{info}" do
        expect(info).to eq("#{input('postgres_user')}")
      end
    end
  end

  sql.query(base_sql % 'r', ["#{dbname}"]).output.split.each do |info|
    describe "DB: #{dbname} - Table" do
      it "Owner: #{info}" do
        expect(info).to eq("#{input('postgres_user')}")
      end
    end
  end

  sql.query(base_sql % 'v', ["#{dbname}"]).output.split.each do |info|
    describe "DB: #{dbname} - View" do
      it "Owner: #{info}" do
        expect(info).to eq("#{input('postgres_user')}")
      end
    end
  end

  sql.query(base_sql % 'm', ["#{dbname}"]).output.split.each do |info|
    describe "DB: #{dbname} - Materialized View" do
      it "Owner: #{info}" do
        expect(info).to eq("#{input('postgres_user')}")
      end
    end
  end

  sql.query(base_sql % 'i', ["#{dbname}"]).output.split.each do |info|
    describe "DB: #{dbname} - Index" do
      it "Owner: #{info}" do
        expect(info).to eq("#{input('postgres_user')}")
      end
    end
  end
  unless sqlversion.match?(/^10/)
    sql.query(base_sql % 'S', ["#{dbname}"]).output.split.each do |info|
      describe "DB: #{dbname} - Sequence" do
        it "Owner: #{info}" do
          expect(info).to eq("#{input('postgres_user')}")
        end
      end
    end

    sql.query(function_sql % "'f','w','a'", ["#{dbname}"]).output.split.each do |info|
      describe "DB: #{dbname} - Function" do
        it "Owner: #{info}" do
          expect(info).to eq("#{input('postgres_user')}")
        end
      end
    end

    sql.query(function_sql % "'p'", ["#{dbname}"]).output.split.each do |info|
      describe "DB: #{dbname} - Stored Procedure" do
        it "Owner: #{info}" do
          expect(info).to eq("#{input('postgres_user')}")
        end
      end
    end
  end

  # Check NON POSTGRES DBs for objects not owned by users in given input list
  sql.query(db_query, ["#{input('postgres_default_db')}"]).output.split.each do |db|
    sql.query(schema_sql, ["#{db}"]).output.split.each do |info|
      describe "DB: #{db} - Schema" do
        it "Owner: #{info}" do
          expect(info).to be_in(sql_owners)
        end
      end
    end

    sql.query(base_sql % 'r', ["#{db}"]).output.split.each do |info|
      describe "DB: #{db} - Table" do
        it "Owner: #{info}" do
          expect(info).to be_in(sql_owners)
        end
      end
    end

    sql.query(base_sql % 'v', ["#{db}"]).output.split.each do |info|
      describe "DB: #{db} - View" do
        it "Owner: #{info}" do
          expect(info).to be_in(sql_owners)
        end
      end
    end

    sql.query(base_sql % 'm', ["#{db}"]).output.split.each do |info|
      describe "DB: #{db} - Materialized View" do
        it "Owner: #{info}" do
          expect(info).to be_in(sql_owners)
        end
      end
    end

    sql.query(base_sql % 'i', ["#{db}"]).output.split.each do |info|
      describe "DB: #{db} - Index" do
        it "Owner: #{info}" do
          expect(info).to be_in(sql_owners)
        end
      end
    end

    next if sqlversion.match?(/^10/)
    sql.query(base_sql % 'S', ["#{db}"]).output.split.each do |info|
      describe "DB: #{db} - Sequence" do
        it "Owner: #{info}" do
          expect(info).to be_in(sql_owners)
        end
      end
    end

    sql.query(function_sql % "'f','w','a'", ["#{db}"]).output.split.each do |info|
      describe "DB: #{db} - Function" do
        it "Owner: #{info}" do
          expect(info).to be_in(sql_owners)
        end
      end
    end

    sql.query(function_sql % "'p'", ["#{db}"]).output.split.each do |info|
      describe "DB: #{db} - Stored Procedure" do
        it "Owner: #{info}" do
          expect(info).to be_in(sql_owners)
        end
      end
    end
  end
end
