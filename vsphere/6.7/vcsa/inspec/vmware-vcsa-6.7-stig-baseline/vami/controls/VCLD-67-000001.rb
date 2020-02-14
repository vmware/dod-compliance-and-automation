control "VCLD-67-000001" do
  title "VAMI must limit the number of simultaneous requests."
  desc  "Denial of Service is one threat against web servers.  Many DoS attacks
attempt to consume web server resources in such a way that no more resources
are available to satisfy legitimate requests.  Mitigation against these threats
is to take steps to  limit the number of resources that can be consumed in
certain ways.

    Lighttpd provides the maxConnections attribute of the <Connector Elements>
to limit the number of concurrent TCP connections."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000001-WSR-000001"
  tag gid: nil
  tag rid: "VCLD-67-000001"
  tag stig_id: "VCLD-67-000001"
  tag cci: "CCI-000054"
  tag nist: ["AC-10", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

grep \"server.max-connections = 1024\" /opt/vmware/etc/lighttpd/lighttpd.conf

If the \"server.max-connections\" is not set to \"1024\", commented out, or
does not exist, this is a finding.


"
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the \"lighttpd.conf\" file with the following value:

server.max-connections = 1024"

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['server.max-connections'] do
    it { should eq '1024' }
  end

end

