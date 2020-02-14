control "VCST-67-000027" do
  title "Rsyslog must be configured to monitor and ship Security Token Service
log files."
  desc  "The Security Token Service produces a number of logs that must be
offloaded from the originating system. This information can then be used for
diagnostic purposes, forensics purposes, or other purposes relevant to ensuring
the availability and integrity of the hosted application."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000358-WSR-000163"
  tag gid: nil
  tag rid: "VCST-67-000027"
  tag stig_id: "VCST-67-000027"
  tag cci: "CCI-001851"
  tag nist: ["AU-4 (1)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep -v \"^#\" /etc/vmware-syslog/stig-services-sso.conf

Expected result:

input(type=\"imfile\"
      File=\"/var/log/vmware/sso/*.log\"
      Tag=\"vmidentity\"
      PersistStateInterval=\"200\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/sso/sts-runtime.log.*\"
      Tag=\"sts-runtime\"
      PersistStateInterval=\"200\"
      Severity=\"info\"
      Facility=\"local0\")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Navigate to and open /etc/vmware-syslog/stig-services-sso.conf ,
creating the file if it does not exist.

Set the contents of the file as follows:

input(type=\"imfile\"
      File=\"/var/log/vmware/sso/*.log\"
      Tag=\"vmidentity\"
      PersistStateInterval=\"200\"
      Severity=\"info\"
      Facility=\"local0\")
input(type=\"imfile\"
      File=\"/var/log/vmware/sso/sts-runtime.log.*\"
      Tag=\"sts-runtime\"
      PersistStateInterval=\"200\"
      Severity=\"info\"
      Facility=\"local0\")"

  describe file('/etc/vmware-syslog/stig-services-sso.conf') do
    it { should exist }
  end
  describe command('grep -v "^#" /etc/vmware-syslog/stig-services-sso.conf') do
    its ('stdout') { should match "input(type=\"imfile\" File=\"/var/log/vmware/sso/*.log\"\nTag=\"vmidentity\"\nPersistStateInterval=\"200\"\nSeverity=\"info\"\nFacility=\"local0\")\ninput(type=\"imfile\" File=\"/var/log/vmware/sso/sts-runtime.log.*\"\nTag=\"sts-runtime\"\nPersistStateInterval=\"200\"\nSeverity=\"info\"\nFacility=\"local0\")\n" }
  end

end