control 'VCRP-70-000004' do
  title 'Envoy must use only TLS 1.2 for the protection of client connections.'
  desc  "
    Envoy can be configured to support TLS 1.0, 1.1 and 1.2. Due to intrinsic problems in TLS 1.0 and TLS 1.1, they are disabled by default. The <protocol> block in the rhttproxy configuration is commented out by default and this configuration forces TLS 1.2.

    The block may also be set to \"tls1.2\" in certain upgrade scenarios but the effect is the same. Uncommenting the block and enabling older protocols is possible and therefore TLS 1.2 restriction must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/config/vmacore/ssl/protocols' /etc/vmware-rhttpproxy/config.xml

    Expected result:

    XPath set is empty

    or

    <protocols>tls1.2</protocols>

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/vmware-rhttpproxy/config.xml

    Locate the <config>/<vmacore>/<ssl> block and configure <protocols> as follows:

    <protocols>tls1.2</protocols>

    Restart the service for changes to take effect.

    # vmon-cli --restart rhttpproxy
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag satisfies: ['SRG-APP-000172-WSR-000104', 'SRG-APP-000439-WSR-000151', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000439-WSR-000156', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCRP-70-000004'
  tag cci: ['CCI-000197', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'SC-8', 'SC-8 (2)']

  value = input('protocols')

  describe.one do
    describe xml("#{input('configXmlPath')}") do
      its(['/config/vmacore/ssl/protocols']) { should cmp value }
    end

    describe xml("#{input('configXmlPath')}") do
      its(['/config/vmacore/ssl/protocols']) { should cmp [] }
    end
  end
end
