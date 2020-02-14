control "VCLD-67-000014" do
  title "Rsyslog must be configured to monitor VAMI logs."
  desc  "For performance reasons, rsyslog file monitoring is preferred over
configuring VAMI to send events to a syslog facility. Without ensuring that
logs are created, that rsyslog configs are created and that those configs are
loaded, the log file monitoring and shipping will not be effective."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000125-WSR-000071"
  tag gid: nil
  tag rid: "VCLD-67-000014"
  tag stig_id: "VCLD-67-000014"
  tag cci: "CCI-001348"
  tag nist: ["AU-9 (2)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep -v \"^#\" /etc/vmware-syslog/stig-services-vami.conf

Expected result:

input(type=\"imfile\" File=\"/opt/vmware/var/log/lighttpd/access.log\"
Tag=\"vami-access\"
Severity=\"info\"
Facility=\"local0\")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result above, this is
a finding."
  desc 'fix', "Navigate to and open
/etc/vmware-syslog/vmware-syslog/stig-services-vami.conf , creating the file if
it does not exist.

Set the contents of the file as follows:

input(type=\"imfile\" File=\"/opt/vmware/var/log/lighttpd/access.log\"
Tag=\"vami-access\"
Severity=\"info\"
Facility=\"local0\")"

  describe file('/etc/vmware-syslog/stig-services-vami.conf') do
    it { should exist }
  end
  describe command('grep -v "^#" /etc/vmware-syslog/stig-services-vami.conf') do
    its ('stdout') { should match "input(type=\"imfile\" File=\"/opt/vmware/var/log/lighttpd/access.log\"\nTag=\"vami-access\"\nSeverity=\"info\"\nFacility=\"local0\")\n" }
  end

end

