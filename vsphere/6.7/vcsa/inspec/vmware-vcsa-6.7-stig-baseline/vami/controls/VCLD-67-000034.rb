control "VCLD-67-000034" do
  title "VAMI must use an approved TLS version for encryption."
  desc  "Transport Layer Security (TLS) is a required transmission protocol for
a web server hosting controlled information. The use of TLS provides
confidentiality of data in transit between the web server and client. FIPS
140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions
must be disabled.

    NIST SP 800-52 defines the approved TLS versions for government
applications."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000439-WSR-000156"
  tag gid: nil
  tag rid: "VCLD-67-000034"
  tag stig_id: "VCLD-67-000034"
  tag cci: "CCI-002418"
  tag nist: ["SC-8", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

Note:  The command should return 2 outputs: ssl.use-sslv2 and ssl.use-sslv3

grep '^ssl.use' /opt/vmware/etc/lighttpd/lighttpd.conf

If any returned value is set to \"enable\" other than \"ssl.use-tlsv12\", this
is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Replace any and all \"ssl.use-*\" lines with following:

ssl.use-sslv2 = \"disable\"
ssl.use-sslv3 = \"disable\"
ssl.use-tlsv10 = \"disable\"
ssl.use-tlsv11 = \"disable\"
ssl.use-tlsv12 = \"enable\""

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['ssl.use-sslv2'] do
    it { should eq "\"disable\"" }
  end
  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['ssl.use-sslv3'] do
    it { should eq "\"disable\"" }
  end
  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['ssl.use-tlsv10'] do
    it { should eq "\"disable\"" }
  end
  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['ssl.use-tlsv11'] do
    it { should eq "\"disable\"" }
  end
  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['ssl.use-tlsv12'] do
    it { should eq "\"enable\"" }
  end

end

