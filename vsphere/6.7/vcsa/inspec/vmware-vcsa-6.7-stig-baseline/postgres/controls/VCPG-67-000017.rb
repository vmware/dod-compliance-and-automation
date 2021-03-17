control "VCPG-67-000017" do
  title "The vPostgres must not allow access to unauthorized accounts."
  desc  "An isolation boundary provides access control and protects the
integrity of the hardware, software, and firmware that perform security
functions.

    Security functions are the hardware, software, and/or firmware of the
information system responsible for enforcing the system security policy and
supporting the isolation of code and data on which the protection is based.

    Developers and implementers can increase the assurance in security
functions by employing well-defined security policy models; structured,
disciplined, and rigorous hardware and software development techniques; and
sound system/security engineering principles.

    Database Management Systems typically separate security functionality from
non-security functionality via separate databases or schemas. Database objects
or code implementing security functionality should not be commingled with
objects or code implementing application logic. When security and non-security
functionality are commingled, users who have access to non-security
functionality may be able to access security functionality."
  impact 0.5
  tag severity: "CAT II"
  tag component: "postgres"
  tag gtitle: "SRG-APP-000233-DB-000124"
  tag gid: nil
  tag rid: "VCPG-67-000017"
  tag stig_id: "VCPG-67-000017"
  tag cci: "CCI-001084"
  tag nist: ["SC-3", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"\\dp .*.;\"

Review the Access Privilege column for all Schemas listed as
\"information_schema\" and \"pg_catalog\".  If access privilege is granted to
any users other than \"postgres\", this is a finding."
  desc 'fix', "At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"REVOKE ALL PRIVILEGES
ON <name> FROM <user>;\"

Replace <name> and <user> with the Access Privilege name and account,
respectively, discovered during the check."

  describe command("psql -U postgres -c '\\dp .*.;' | awk -F'|' '{print $4}' | grep -v 'Access' | sed -r '/^\s*$/d' | cut -d'+' -f1 | grep -v -E 'postgres=|=r|w/postgres'") do
    its ('stdout.strip') { should cmp '' }
  end
end

