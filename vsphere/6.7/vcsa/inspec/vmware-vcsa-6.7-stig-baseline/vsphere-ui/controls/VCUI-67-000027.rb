control "VCUI-67-000027" do
  title "vSphere UI log files must be moved to a permanent repository in
accordance with site policy."
  desc  "vSphere UI produces a handful of logs that must be offloaded from the
originating system. This information can then be used for diagnostic purposes,
forensics purposes, or other purposes relevant to ensuring the availability and
integrity of the hosted application."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000358-WSR-000163"
  tag rid: "VCUI-67-000027"
  tag stig_id: "VCUI-67-000027"
  tag cci: "CCI-001851"
  tag nist: ["AU-4 (1)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep -v \"^#\" /etc/vmware-syslog/stig-services-vsphere-ui.conf

Expected result:

input(type=\"imfile\"

      File=\"/var/log/vmware/vsphere-ui/logs/access/localhost_access*\"

      Tag=\"ui-access\"

      Severity=\"info\"

      Facility=\"local0\")

input(type=\"imfile\"

      File=\"/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime*\"

      Tag=\"ui-runtime\"

      Severity=\"info\"

      Facility=\"local0\")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Navigate to and open
/etc/vmware-syslog/stig-services-vsphere-ui.conf , creating the file if it does
not exist.

Set the contents of the file as follows:

input(type=\"imfile\"
      File=\"/var/log/vmware/vsphere-ui/logs/access/localhost_access*\"
      Tag=\"ui-access\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime*\"
      Tag=\"ui-runtime\"
      Severity=\"info\"
      Facility=\"local0\")"

  describe file('/etc/vmware-syslog/stig-services-vsphere-ui.conf') do
    it { should exist }
  end
  describe command('grep -v "^#" /etc/vmware-syslog/stig-services-vsphere-ui.conf') do
    its ('stdout') { should match "input(type=\"imfile\"\n      File=\"/var/log/vmware/vsphere-ui/logs/access/localhost_access*\"\n      Tag=\"ui-access\"\n      Severity=\"info\"\n      Facility=\"local0\")\ninput(type=\"imfile\"\n      File=\"/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime*\"\n      Tag=\"ui-runtime\"\n      Severity=\"info\"\n      Facility=\"local0\")\n" }
  end

end
