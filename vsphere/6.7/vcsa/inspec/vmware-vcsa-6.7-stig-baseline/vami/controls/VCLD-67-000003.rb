control "VCLD-67-000003" do
  title "VAMI must use cryptography to protect the integrity of remote
sessions."
  desc  "Data exchanged between the user and the web server can range from
static display data to credentials used to log into the hosted application.
Even when data appears to be static, the non-displayed logic in a web page may
expose business logic or trusted system relationships. The integrity of all the
data being exchanged between the user and web server must always be trusted. To
protect the integrity and trust, encryption methods should be used to protect
the complete communication session.

    In order to protect the integrity and confidentiality of the remote
sessions, Lighttpd uses SSL/TLS."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000015-WSR-000014"
  tag gid: nil
  tag rid: "VCLD-67-000003"
  tag stig_id: "VCLD-67-000003"
  tag cci: "CCI-001453"
  tag nist: ["AC-17 (2)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

grep '^ssl.engine' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value \"ssl.engine\" is not set to \"enable\", this is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the \"lighttpd.conf\" file with the following value:

ssl.engine = \"enable\""

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['ssl.engine'] do
    it { should eq "\"enable\"" }
  end

end

