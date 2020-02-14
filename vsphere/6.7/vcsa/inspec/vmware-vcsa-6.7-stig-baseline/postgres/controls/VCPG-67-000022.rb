control "VCPG-67-000022" do
  title "Rsyslog must be configured to monitor vPostgres logs."
  desc  "For performance reasons, rsyslog file monitoring is preferred over
configuring vPostgres to send events to a syslog facility. Without ensuring
that logs are created, that rsyslog configs are create and that those configs
are loaded, the log file monitoring and shipping will not be effective."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000359-DB-000319"
  tag gid: nil
  tag rid: "VCPG-67-000022"
  tag stig_id: "VCPG-67-000022"
  tag cci: "CCI-001855"
  tag nist: ["AU-5 (1)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# cat /etc/vmware-syslog/stig-services-vpostgres.conf

Expected result:

input(type=\"imfile\"
File=\"/var/log/vmware/vpostgres/serverlog.std*\"
Tag=\"vpostgres-first\"
Severity=\"info\"
Facility=\"local0\")

input(type=\"imfile\"
File=\"/var/log/vmware/vpostgres/postgresql-*.log\"
Tag=\"vpostgres\"
Severity=\"info\"
Facility=\"local0\")


If the file does not exist, this is a finding.

If the output of the command does not match the expected result above, this is
a finding.

If there is no output from the command, vPostgres will default to \"stderr\",
this is not a finding."
  desc 'fix', "Navigate to and open
/etc/vmware-syslog/stig-services-vpostgres.conf, creating the file if it does
not exist.

Set the contents of the file as follows:

input(type=\"imfile\"
File=\"/var/log/vmware/vpostgres/serverlog.std*\"
Tag=\"vpostgres-first\"
Severity=\"info\"
Facility=\"local0\")

input(type=\"imfile\"
File=\"/var/log/vmware/vpostgres/postgresql-*.log\"
Tag=\"vpostgres\"
Severity=\"info\"
Facility=\"local0\")

"

  describe file('/etc/vmware-syslog/stig-services-vpostgres.conf') do
    it { should exist }
  end
  describe command('grep -v "^#" /etc/vmware-syslog/stig-services-vpostgres.conf') do
    its ('stdout') { should match "input(type=\"imfile\"\nFile=\"/var/log/vmware/vpostgres/serverlog.std*\"\nTag=\"vpostgres-first\"\nSeverity=\"info\"\nFacility=\"local0\")\n\ninput(type=\"imfile\"\nFile=\"/var/log/vmware/vpostgres/postgresql-*.log\"\nTag=\"vpostgres\"\nSeverity=\"info\"\nFacility=\"local0\")\n" }
  end

end

