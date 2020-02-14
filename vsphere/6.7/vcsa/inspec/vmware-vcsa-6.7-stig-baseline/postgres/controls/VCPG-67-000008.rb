control "VCPG-67-000008" do
  title "vPostgres database objects must only be accessible to the postgres
account."
  desc  "Within the database, object ownership implies full privileges to the
owned object, including the privilege to assign access to the owned objects to
other subjects. Database functions and procedures can be coded using definer's
rights. This allows anyone who utilizes the object to perform the actions if
they were the owner. If not properly managed, this can lead to privileged
actions being taken by unauthorized individuals.

    Conversely, if critical tables or other objects rely on unauthorized owner
accounts, these objects may be lost when an account is removed."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000133-DB-000200"
  tag gid: nil
  tag rid: "VCPG-67-000008"
  tag stig_id: "VCPG-67-000008"
  tag cci: "CCI-001499"
  tag nist: ["CM-5 (6)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -d VCDB -x -U postgres -c
\"\\dt;\"|grep Owner|grep -v vc

If any output if returned, this is a finding."
  desc 'fix', "At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER TABLE
<tablename> OWNER TO vc;\"

Replace <tablename> with the name of the table discovered during the check.
"

  describe postgres_session('postgres','','localhost').query("SELECT * FROM pg_tables WHERE schemaname = \'vc\' and tableowner != \'vc\';",['VCDB']) do
    its('output') {should eq ""}
  end

end

