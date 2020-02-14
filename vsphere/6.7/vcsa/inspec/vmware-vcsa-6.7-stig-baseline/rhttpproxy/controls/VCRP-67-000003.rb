control "VCRP-67-000003" do
  title "rhttpproxy must be configured to operate solely with FIPS ciphers."
  desc  "rhttpproxy ships with FIPS validated OpenSSL cryptographic libraries
and can be configured to run in FIPS mode for protection of data-in-transit
over the client TLS connection."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000014-WSR-000006"
  tag gid: nil
  tag rid: "VCRP-67-000003"
  tag stig_id: "VCRP-67-000003"
  tag cci: "CCI-000068"
  tag nist: ["AC-17 (2)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --xpath '/config/vmacore/ssl/fips' /etc/vmware-rhttpproxy/config.xml

Expected result:

<fips>true</fips>

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open /etc/vmware-rhttpproxy/config.xml

Locate the <ssl> block inside of the <vmacore> block and configure <fips> as
follows:

<fips>true</fips>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy"

  describe xml('/etc/vmware-rhttpproxy/config.xml') do
    its(['/config/vmacore/ssl/fips']) { should cmp ['true'] }
  end

end

