control "VCLD-67-000002" do
  title "VAMI must be configured with FIPS 140-2 compliant ciphers for HTTPS
connections."
  desc  "Encryption of data-in-flight is an essential element of protecting
information confidentiality.  If a web server uses weak or outdated encryption
algorithms, then the server's communications can potentially be compromised.

    The US Federal Information Processing Standards (FIPS) publication 140-2,
Security Requirements for Cryptographic Modules (FIPS 140-2) identifies eleven
areas for a cryptographic module used inside a security system that protects
information.  FIPS 140-2 approved ciphers provide the maximum level of
encryption possible for a private web server.

    Configuration of ciphers used by TC Server are set in the
catalina.properties file.  Only those ciphers specified in the configuration
file, and which are available in the installed OpenSSL library, will be used by
TC Server while encrypting data for transmission."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000014-WSR-000006"
  tag gid: nil
  tag rid: "VCLD-67-000002"
  tag stig_id: "VCLD-67-000002"
  tag cci: "CCI-000068"
  tag nist: ["AC-17 (2)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

/opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf|grep \"ssl.cipher-list\"

If the value ssl.cipher-list = \"FIPS:!aNULL:!eNULL\" is not returned or
commented out, this is a finding."
  desc 'fix', "Navigate to and open /etc/applmgmt/appliance/lighttpd.conf

Remove any existing \"ssl.cipher-list\" entry and repalce with the following:

ssl.cipher-list = \"FIPS:!aNULL:!eNULL\""

  describe parse_config_file('/etc/applmgmt/appliance/lighttpd.conf').params['ssl.cipher-list'] do
    it { should eq "\"FIPS:!aNULL:!eNULL\"" }
  end

end

