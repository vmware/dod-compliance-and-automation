control "VCFL-67-000027" do
  title "Rsyslog must be configured to monitor and ship vSphere Client log
files."
  desc  "The vSphere Client produces a handful of logs that must be offloaded
from the originating system. This information can then be used for diagnostic
purposes, forensics purposes, or other purposes relevant to ensuring the
availability and integrity of the hosted application."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000358-WSR-000163"
  tag gid: nil
  tag rid: "VCFL-67-000027"
  tag stig_id: "VCFL-67-000027"
  tag cci: "CCI-001851"
  tag nist: ["AU-4 (1)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep -v \"^#\" /etc/vmware-syslog/stig-vsphere-client.conf

Expected result:

input(type=\"imfile\"
      File=\"/var/log/vmware/vsphere-client/logs/access/localhost_access*\"
      Tag=\"client-access\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/vsphere-client/logs/vsphere-client-runtime*\"
      Tag=\"client-runtime\"
      Severity=\"info\"
      Facility=\"local0\")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Navigate to and open /etc/vmware-syslog/stig-vsphere-client.conf ,
creating the file if it does not exist.

Set the contents of the file as follows:

input(type=\"imfile\"
      File=\"/var/log/vmware/vsphere-client/logs/access/localhost_access*\"
      Tag=\"client-access\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/vsphere-client/logs/vsphere-client-runtime*\"
      Tag=\"client-runtime\"
      Severity=\"info\"
      Facility=\"local0\")"

  describe file('/etc/vmware-syslog/stig-vsphere-client.conf') do
    it { should exist }
  end
  describe command('grep -v "^#" /etc/vmware-syslog/stig-vsphere-client.conf') do
    its ('stdout') { should match "input(type=\"imfile\" File=\"/var/log/vmware/vsphere-client/logs/access/localhost_access*\"\nTag=\"vami-access\"\nSeverity=\"info\"\nFacility=\"local0\")\ninput(type=\"imfile\" File=\"/var/log/vmware/vsphere-client/logs/vsphere-client-runtime*\"\nTag=\"ui-runtime\"\nSeverity=\"info\"\nFacility=\"local0\")\n" }
  end

end