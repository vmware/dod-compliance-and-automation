control 'VCFA-9X-000375' do
  title 'VMware Cloud Foundation Automation must disable unused feature flags.'
  desc  'VCF Automation can ship with alpha features that are still under development but in a state where some customers may find them useful. If not used these features should be disabled to reduce attack surface and risk that may be present in features not considered production ready.'
  desc  'rationale', ''
  desc  'check', "
    If VCF Automation is not deployed, this is not applicable.

    From the VCF Automation Tenant Manager, go to Administration >> Feature Flags.

    Review the enabled feature flags and determine if any feature flags are enabled that are not actively used in the environment.

    If any feature flags are enabled and not actively used, this is a finding.
  "
  desc 'fix', "
    From the VCF Automation Tenant Manager, go to Administration >> Feature Flags.

    Click the menu button next to the target feature flag and select \"Disable\".
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000375'
  tag rid: 'SV-VCFA-9X-000375'
  tag stig_id: 'VCFA-9X-000375'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('automation_deployed')
    approvedFlags = input('automation_approvedFeatureFlags')
    result = http("https://#{input('automation_url')}/cloudapi/1.0.0/featureFlags",
                  method: 'GET',
                  headers: {
                    'Accept' => "#{input('automation_apiVersion')}",
                    'Authorization' => "Bearer #{input('automation_sessionToken')}"
                  },
                  ssl_verify: false)

    describe result do
      its('status') { should cmp 200 }
    end
    unless result.status != 200
      features = JSON.parse(result.body)
      features['values'].each do |feature|
        if approvedFlags.include?(feature['displayName'])
          describe "Approved feature flag: #{feature['displayName']} enabled" do
            subject { feature['enabled'] }
            it { should cmp 'true' }
          end
        else
          describe "Unknown Feature flag: #{feature['displayName']} enabled" do
            subject { feature['enabled'] }
            it { should cmp 'false' }
          end
        end
      end
    end
  else
    impact 0.0
    describe 'VCF Automation is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Automation is not deployed in the target environment. This control is N/A.'
    end
  end
end
