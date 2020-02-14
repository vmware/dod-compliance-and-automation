control "VCRP-67-000009" do
  title "rhttpproxy log files must be moved to a permanent repository in
accordance with site policy."
  desc  "rhttpproxy produces a handful of logs that must be offloaded from the
originating system. This information can then be used for diagnostic purposes,
forensics purposes, or other purposes relevant to ensuring the availability and
integrity of the hosted application."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000358-WSR-000063"
  tag gid: nil
  tag rid: "VCRP-67-000009"
  tag stig_id: "VCRP-67-000009"
  tag cci: "CCI-001851"
  tag nist: ["AU-4 (1)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep -v \"^#\" /etc/vmware-syslog/stig-services-rhttproxy.conf

Expected result:

input(type=\"imfile\"
      File=\"/var/log/vmware/rhttpproxy/rhttpproxy.log\"
      Tag=\"rhttpproxy-main\"
      Severity=\"info\"
      Facility=\"local0\")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Navigate to and open
/etc/vmware-syslog/stig-services-rhttproxy.conf , creating the file if it does
not exist.

Set the contents of the file as follows:

input(type=\"imfile\"
      File=\"/var/log/vmware/rhttpproxy/rhttpproxy.log\"
      Tag=\"rhttpproxy-main\"
      Severity=\"info\"
      Facility=\"local0\")"

  describe file('/etc/vmware-syslog/stig-services-rhttproxy.conf') do
    it { should exist }
  end
  describe command('grep -v "^#" /etc/vmware-syslog/stig-services-rhttproxy.conf') do
    its ('stdout') { should match "input(type=\"imfile\" File=\"/var/log/vmware/rhttpproxy/rhttpproxy.log\"\nTag=\"rhttpproxy-main\"\nSeverity=\"info\"\nFacility=\"local0\")\n" }
  end

end

