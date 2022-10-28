control 'VCSA-70-000077' do
  title 'The vCenter Server must enable FIPS validated cryptography.'
  desc  "
    FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.

    In vSphere 6.7 and later, ESXi and vCenter Server use FIPS-validated cryptography to protect management interfaces and the VMware Certificate Authority (VMCA).

    vSphere 7.0 Update 2 and later adds additional FIPS-validated cryptography to vCenter Server Appliance. By default, this FIPS validation option is disabled and must be enabled.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Web Client go to Developer Center >> API Explorer.

    From the Select API drop-down menu, select appliance.

    Expand system/security/global_fips >> Get.

    Click execute and then Copy Response to view the results.

    Example response:

    {
        \"enabled\": true
    }

    If global FIPS mode is not enabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Web Client go to Developer Center >> API Explorer.

    From the Select API drop-down menu, select appliance.

    Expand system/security/global_fips >> Put.

    In the response body under \"Try it out\" paste the following:

    {
        \"enabled\": true
    }

    Click Execute.

    Note: The vCenter server reboots after you enable or disable FIPS.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000172'
  tag satisfies: ['SRG-APP-000179', 'SRG-APP-000224', 'SRG-APP-000231', 'SRG-APP-000412', 'SRG-APP-000514', 'SRG-APP-000555', 'SRG-APP-000600', 'SRG-APP-000610', 'SRG-APP-000620', 'SRG-APP-000630', 'SRG-APP-000635']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000077'
  tag cci: ['CCI-000197', 'CCI-000803', 'CCI-001188', 'CCI-001199', 'CCI-001967', 'CCI-002450', 'CCI-003123']
  tag nist: ['IA-3 (1)', 'IA-5 (1) (c)', 'IA-7', 'MA-4 (6)', 'SC-13', 'SC-23 (3)', 'SC-28']

  result = http("https://#{input('vcURL')}/api/appliance/system/global-fips",
              method: 'GET',
              headers: {
                'vmware-api-session-id' => "#{input('vcApiToken')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its(['enabled']) { should cmp 'true' }
    end
  end
end
