control "VCPG-67-000009" do
  title "The vPostgres database must limit modify privileges to authorized
accounts."
  desc  "If the DBMS were to allow any user to make changes to database
structure or logic, then those changes might be implemented without undergoing
the appropriate testing and approvals that are part of a robust change
management process.

    Accordingly, only qualified and authorized individuals shall be allowed to
obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.

    Unmanaged changes that occur to the database software libraries or
configuration can lead to unauthorized or compromised installations."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000133-DB-000362"
  tag gid: nil
  tag rid: "VCPG-67-000009"
  tag stig_id: "VCPG-67-000009"
  tag cci: "CCI-001499"
  tag nist: ["CM-5 (6)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"\\du;\"|grep
\"Create\"

If the accounts other than \"postgres\" and \"vc\" have \"create\" privileges,
this is a finding."
  desc 'fix', "At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"REVOKE ALL PRIVILEGES
FROM <user>;\"

Replace <user> with the account discovered during the check."

  describe postgres_session('postgres','','localhost').query("SELECT * FROM pg_roles WHERE rolcreatedb = \'t\' or rolcreaterole = \'t\';") do
    its('output.strip') { should match /^postgres.*$/ }
    its('output.strip') { should match /^vc.*$/ }
  end

end

