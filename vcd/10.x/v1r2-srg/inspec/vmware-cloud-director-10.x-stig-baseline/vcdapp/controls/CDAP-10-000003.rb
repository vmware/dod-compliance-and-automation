control 'CDAP-10-000003' do
  title 'VMware Cloud Director must implement FIPS 140-2 approved TLS versions.'
  desc  "
    Encryption is critical for protection of remote access sessions. If encryption is not being used for integrity, malicious users may gain the ability to modify the application server configuration. The use of cryptography for ensuring integrity of remote access sessions mitigates that risk.

    Application servers utilize a web management interface and scripted commands when allowing remote access. Web access requires the use of TLS and scripted access requires using ssh or some other form of approved cryptography. Application servers must have a capability to enable a secure remote admin capability.

    FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

    NIST SP 800-52 specifies the preferred configurations for government systems.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify TLS 1.2 or TLS 1.3 are the only protocols in use by running the following command on each appliance:

    # /opt/vmware/vcloud-director/bin/cell-management-tool ssl-protocols -l

    Example output:

    Allowed SSL protocols:
    * TLSv1.3
    * TLSv1.2

    If any protocol is enabled other than TLSv1.2 or TLSv1.3, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # /opt/vmware/vcloud-director/bin/cell-management-tool ssl-protocols -d \"TLSv1,TLSv1.1\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag satisfies: ['SRG-APP-000439-AS-000155', 'SRG-APP-000440-AS-000167', 'SRG-APP-000441-AS-000258', 'SRG-APP-000442-AS-000259']
  tag gid: 'V-CDAP-10-000003'
  tag rid: 'SV-CDAP-10-000003'
  tag stig_id: 'CDAP-10-000003'
  tag cci: ['CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'SC-8', 'SC-8 (1)', 'SC-8 (2)']

  allowedProtocols = input('allowedTLSProtocols')

  result = http("https://#{input('vcdURL')}/cloudapi/1.0.0/ssl/settings",
                method: 'GET',
                headers: {
                  'Accept' => "#{input('apiVersion')}",
                  'Authorization' => "#{input('bearerToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    enabledProtocols = json(content: result.body)['enabledSslProtocols']

    enabledProtocols.each do |protocol|
      describe protocol do
        it { should be_in allowedProtocols }
      end
    end
  end
end
