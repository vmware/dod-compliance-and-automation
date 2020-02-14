control "VCPG-67-000012" do
  title "The vPostgres database must be limited to authorized accounts."
  desc  "To assure accountability and prevent unauthenticated access,
organizational users must be identified and authenticated to prevent potential
misuse and compromise of the system.

    Organizational users include organizational employees or individuals the
organization deems to have equivalent status of employees (e.g., contractors).
Organizational users (and any processes acting on behalf of users) must be
uniquely identified and authenticated for all accesses, except the following:

    (i) Accesses explicitly identified and documented by the organization.
Organizations document specific user actions that can be performed on the
information system without identification or authentication; and

    (ii) Accesses that occur through authorized use of group authenticators
without individual authentication. Organizations may require unique
identification of individuals in group accounts (e.g., shared privilege
accounts) or for detailed accountability of individual activity."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000148-DB-000103"
  tag gid: nil
  tag rid: "VCPG-67-000012"
  tag stig_id: "VCPG-67-000012"
  tag cci: "CCI-000764"
  tag nist: ["IA-2", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command to enter the
psql prompt:

# grep -v \"^#\" /storage/db/vpostgres/pg_hba.conf|grep -z --color=always
\"trust\"

If any rows have \"trust\" specified for the \"METHOD\" column, this is a
finding."
  desc 'fix', "Navigate to and open /storage/db/pgdata/pg_hba.conf.

Navigate to the user that has a method of \"trust\".
Change the method to \"md5\".

A correct, typical line will look like the below:
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host       all                        all                 127.0.0.1/32
 md5"

  describe postgres_hba_conf('/storage/db/vpostgres/pg_hba.conf').where {type == 'local'} do
    its ('auth_method') { should_not include 'trust' }
  end

  describe postgres_hba_conf('/storage/db/vpostgres/pg_hba.conf').where {type == 'host'} do
    its ('auth_method') { should_not include 'trust' }
  end

end

