control 'VCRP-70-000004' do
  title 'Envoy must use only Transport Layer Security (TLS) 1.2 for the protection of client connections.'
  desc '<0> [object Object]'
  desc 'check', "At the command prompt, run the following command:

# xmllint --xpath '/config/vmacore/ssl/protocols' /etc/vmware-rhttpproxy/config.xml

Expected result:

XPath set is empty

or

<protocols>tls1.2</protocols>

If the output does not match the expected result, this is a finding."
  desc 'fix', 'Navigate to and open:

/etc/vmware-rhttpproxy/config.xml

Locate the <config>/<vmacore>/<ssl> block and configure <protocols> as follows:

<protocols>tls1.2</protocols>

Restart the service for changes to take effect.

# vmon-cli --restart rhttpproxy'
  impact 0.5
  tag check_id: 'C-60415r889156_chk'
  tag severity: 'medium'
  tag gid: 'V-256740'
  tag rid: 'SV-256740r889158_rule'
  tag stig_id: 'VCRP-70-000004'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-60358r889157_fix'
  tag cci: ['CCI-000197', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002422']
  tag nist: ['IA-5 (1) (c)', 'AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (2)']

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
