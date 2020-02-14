control "VCLD-67-000031" do
  title "VAMI must have debug logging disabled."
  desc  "Information needed by an attacker to begin looking for possible
vulnerabilities in a web server includes any information about the web server
and plug-ins or modules being used. When debugging or trace information is
enabled in a production web server, information about the web server, such as
web server type, version, patches installed, plug-ins and modules installed,
type of code being used by the hosted application, and any backends being used
for data storage may be displayed. Since this information may be placed in logs
and general messages during normal operation of the web server, an attacker
does not need to cause an error condition to gain this information."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000266-WSR-000160"
  tag gid: nil
  tag rid: "VCLD-67-000031"
  tag stig_id: "VCLD-67-000031"
  tag cci: "CCI-001312"
  tag nist: ["SI-11 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

grep '^debug.log-request-handling' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value for \"debug.log-request-handling\" is not set to \"disable\", this
is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the \"lighttpd.conf\" file with the following:

debug.log-request-handling = \"disable\""

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['debug.log-request-handling'] do
    it { should eq "\"disable\"" }
  end

end

