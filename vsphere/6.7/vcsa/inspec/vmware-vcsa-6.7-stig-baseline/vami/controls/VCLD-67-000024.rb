control "VCLD-67-000024" do
  title "VAMI must only listen on localhost."
  desc  "The web server must be configured to listen on a specified IP address
and port. Without specifying an IP address and port for the web server
to utilize, the web server will listen on all IP addresses available to the
hosting server. If the web server has multiple IP addresses, i.e., a
management IP address, the web server will also accept connections on the
management IP address. Accessing the hosted application through an IP
address normally used for non-application functions opens the possibility of
user access to resources, utilities, files, ports, and protocols that are
protected on the desired application IP address."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000142-WSR-000089"
  tag gid: nil
  tag rid: "VCLD-67-000024"
  tag stig_id: "VCLD-67-000024"
  tag cci: "CCI-000382"
  tag nist: ["CM-7 b", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

grep '^server.port' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value of \"server.port\" is not \"5480\" or no value is returned, this
is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf file.

Remove any existing server.port entry and add the following line:

server.port = 5480"

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['server.port'] do
    it { should eq '5480' }
  end

end

