control "VCPG-67-000006" do
  title "The vPostgres database must have the correct ownership on the log
files."
  desc  "If audit data were to become compromised, then competent forensic
analysis and discovery of the true source of potentially malicious system
activity is impossible to achieve.

    To ensure the veracity of audit data the information system and/or the
application must protect audit information from unauthorized modification.

    This requirement can be achieved through multiple methods that will depend
upon system architecture and design. Some commonly employed methods include
ensuring log files enjoy the proper file system permissions and limiting log
data locations.

    Applications providing a user interface to audit data will leverage user
permissions and roles identifying the user accessing the data and the
corresponding rights that the user enjoys in order to make access decisions
regarding the modification of audit data.

    Audit information includes all information (e.g., audit records, audit
settings, and audit reports) needed to successfully audit information system
activity.

    Modification of database audit data could mask the theft of, or the
unauthorized modification of, sensitive data stored in the database."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000119-DB-000060"
  tag gid: nil
  tag rid: "VCPG-67-000006"
  tag stig_id: "VCPG-67-000006"
  tag cci: "CCI-000163"
  tag nist: ["AU-9", "Rev_4"]
  desc 'check', "At the command prompt, enter the following command:

# stat -c \"%n is owned by %U:%G\" /var/log/vmware/vpostgres/*.log

If the ownership of any log files is not \"vpostgres:users\", this is a finding"
  desc 'fix', "At the command prompt, enter the following command:

# chown vpostgres:users <file_name>

Replace <file_name> with files to be modified"

  command('find /var/log/vmware/vpostgres/ -type f -maxdepth 1 -name "*"').stdout.split.each do | fname |
    describe file(fname) do
      its('owner') { should cmp 'vpostgres' }
      its('group') { should cmp 'users' }
    end
  end

end

