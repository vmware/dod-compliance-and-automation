control 'VCRP-67-000004' do
  title "The rhttpproxy must use cryptography to protect the integrity of
remote sessions."
  desc  "The rhttpproxy can be configured to support TLS 1.0, 1.1 and 1.2. Due
to intrinsic problems in TLS 1.0 and TLS 1.1, they are disabled by default. The
$protocol block in the rhttproxy configuration is commented out by default, and
this configuration forces TLS 1.2. The block may also be set to \"tls1.2\" in
certain upgrade scenarios, but the effect is the same."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/config/vmacore/ssl/protocols'
/etc/vmware-rhttpproxy/config.xml

    Expected result:

    <protocols>tls1.2</protocols>

    OR

    XPath set is empty

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open /etc/vmware-rhttpproxy/config.xml.

    Locate the <config>/<vmacore>/<ssl> block and configure <protocols> as
follows:

    <protocols>tls1.2</protocols>

    Restart the service for changes to take effect.

    # vmon-cli --restart rhttpproxy
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag gid: 'V-240719'
  tag rid: 'SV-240719r816678_rule'
  tag stig_id: 'VCRP-67-000004'
  tag fix_id: 'F-43911r679669_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

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
