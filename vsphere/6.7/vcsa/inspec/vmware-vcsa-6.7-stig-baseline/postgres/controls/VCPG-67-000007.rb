control "VCPG-67-000007" do
  title "The vPostgres configuration files must have the correct ownership."
  desc  "Protecting audit data also includes identifying and protecting the
tools used to view and manipulate log data. Therefore, protecting audit tools
is necessary to prevent unauthorized operation on audit data.

    Applications providing tools to interface with audit data will leverage
user permissions and roles identifying the user accessing the tools and the
corresponding rights the user enjoys in order make access decisions regarding
the modification of audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000122-DB-000203"
  tag gid: nil
  tag rid: "VCPG-67-000007"
  tag stig_id: "VCPG-67-000007"
  tag cci: "CCI-001494"
  tag nist: ["AU-9", "Rev_4"]
  desc 'check', "At the command prompt, enter the following command:

# stat -c \"%n is owned by %U:%G\" /storage/db/vpostgres/*.conf

If the ownership of any log files is not \"vpostgres:users\", this is a finding"
  desc 'fix', "At the command prompt, enter the following command:

# chown vpostgres:users <file_name>

Replace <file_name> with files to be modified"

  command('find /storage/db/vpostgres/ -type f -maxdepth 1 -name "*conf*"').stdout.split.each do | fname |
    describe file(fname) do
      its('owner') { should cmp 'vpostgres' }
      its('group') { should cmp 'users' }
    end
  end

end

