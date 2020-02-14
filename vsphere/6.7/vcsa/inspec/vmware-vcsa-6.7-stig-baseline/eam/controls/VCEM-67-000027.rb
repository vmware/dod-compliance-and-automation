control "VCEM-67-000027" do
  title "Rsyslog must be configured to monitor and ship ESX Agent Manager log
files."
  desc  "ESX Agent Manager a number of logs that must be offloaded from the
originating system. This information can then be used for diagnostic purposes,
forensics purposes, or other purposes relevant to ensuring the availability and
integrity of the hosted application."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000358-WSR-000163"
  tag gid: nil
  tag rid: "VCEM-67-000027"
  tag stig_id: "VCEM-67-000027"
  tag cci: "CCI-001851"
  tag nist: ["AU-4 (1)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep -v \"^#\" /etc/vmware-syslog/stig-services-eam.conf

Expected result:

input(type=\"imfile\"
      File=\"/var/log/vmware/eam/eam.log\"
      Tag=\"eam-main\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/eam/web/localhost_access_log*.txt\"
      Tag=\"eam-access\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/eam/jvm.log.std*\"
      Tag=\"eam-stdout\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/eam/web/catalina*.log\"
      Tag=\"eam-catalina\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/eam/web/localhost.*.log\"
      Tag=\"eam-catalina\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/firstboot/eam_firstboot.py*.log\"
      Tag=\"eam-firstboot\"
      Severity=\"info\"
      Facility=\"local0\")
File=\"/var/log/vmware/firstboot/eam_firstboot.py*.log\"
      Tag=\"eam-firstboot\"
      Severity=\"info\"
      Facility=\"local0\")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Navigate to and open /etc/vmware-syslog/stig-services-eam.conf ,
creating the file if it does not exist.

Set the contents of the file as follows:

input(type=\"imfile\"
      File=\"/var/log/vmware/eam/eam.log\"
      Tag=\"eam-main\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/eam/web/localhost_access_log*.txt\"
      Tag=\"eam-access\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/eam/jvm.log.std*\"
      Tag=\"eam-stdout\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/eam/web/catalina*.log\"
      Tag=\"eam-catalina\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/eam/web/localhost.*.log\"
      Tag=\"eam-catalina\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/firstboot/eam_firstboot.py*.log\"
      Tag=\"eam-firstboot\"
      Severity=\"info\"
      Facility=\"local0\")"

  describe file('/etc/vmware-syslog/stig-services-eam.conf') do
    it { should exist }
  end
  describe command('grep -v "^#" /etc/vmware-syslog/stig-services-eam.conf') do
    its ('stdout') { should match "input(type=\"imfile\" File=\"/var/log/vmware/eam/eam.log\"\nTag=\"eam-main\"\nSeverity=\"info\"\nFacility=\"local0\")\ninput(type=\"imfile\"\nFile=\"/var/log/vmware/eam/web/localhost_access_log*.txt\"\nTag=\"eam-access\"\nSeverity=\"info\"\nFacility=\"local0\")\ninput(type=\"imfile\"\nFile=\"/var/log/vmware/eam/jvm.log.std*\"\nTag=\"eam-stdout\"\nSeverity=\"info\"\nFacility=\"local0\")\ninput(type=\"imfile\"\nFile=\"/var/log/vmware/eam/web/catalina*.log\"\nTag=\"eam-catalina\"\nSeverity=\"info\"\nFacility=\"local0\")\ninput(type=\"imfile\"\nFile=\"/var/log/vmware/eam/web/localhost.*.log\"\nTag=\"eam-catalina\"\nSeverity=\"info\"\nFacility=\"local0\")\ninput(type=\"imfile\"\nFile=\"/var/log/vmware/firstboot/eam_firstboot.py*.log\"\nTag=\"eam-firstboot\"\nSeverity=\"info\"\nFacility=\"local0\")\n" }
  end

end

