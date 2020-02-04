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
  tag fix_id: nil
  tag cci: "CCI-000068"
  tag nist: ["AC-17 (2)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AC-17 (2)"
  tag check: "At the command prompt, execute the following command:

# sed -n \"/    <ssl>/,/ssl>/p\" /etc/vmware-rhttpproxy/config.xml|grep -z
--color=always 'fips'

If the value of 'fips' is not set to 'true', is missing or is commented, this
is a finding."
  tag fix: "Navigate to and open /etc/vmware-rhttpproxy/config.xml

Locate the <ssl> block inside of the <vmacore> block and configure <fips> as
follows:

<fips>true</fips>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy"

  describe xml('/etc/vmware-rhttpproxy/config.xml') do
    its(['/config/vmacore/ssl/fips']) { should cmp ['true'] }
  end

end