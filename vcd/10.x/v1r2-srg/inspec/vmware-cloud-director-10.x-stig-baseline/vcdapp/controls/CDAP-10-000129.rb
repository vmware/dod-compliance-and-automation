control 'CDAP-10-000129' do
  title 'Cloud Director must enable hostname certificate verification for vCenter connections.'
  desc  'VMware Cloud Director always verifies the certificates for vCenter by default. When enabled, this setting adds an additional step to verify the host names in the vCenter Server certificates.'
  desc  'rationale', ''
  desc  'check', "
    From the Cloud Director provider interface, go to Administration >> Settings >> General >> Certificates.

    View the \"Use hostname verification for vCenter Server and vSphere Certificates\" setting.

    If \"Use hostname verification for vCenter Server and vSphere Certificates\" is not enabled, this is a finding.
  "
  desc 'fix', "
    From the Cloud Director provider interface, go to Administration >> Settings >> General >> Certificates.

    Click Edit.

    Enable the radio button next to \"Use hostname verification for vCenter Server and vSphere Certificates\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CDAP-10-000129'
  tag rid: 'SV-CDAP-10-000129'
  tag stig_id: 'CDAP-10-000129'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('vcdURL')}/api/admin/extension/settings/general",
                method: 'GET',
                headers: {
                  'accept' => "#{input('legacyApiVersion')}",
                  'Authorization' => "#{input('bearerToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its(['verifyVcCertificates']) { should cmp 'true' }
    end
  end
end
