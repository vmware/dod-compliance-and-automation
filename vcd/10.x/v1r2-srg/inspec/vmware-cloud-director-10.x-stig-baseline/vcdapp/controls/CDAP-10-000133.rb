control 'CDAP-10-000133' do
  title 'Cloud Director must disable alpha features.'
  desc  'Cloud Director can ship with alpha features that are still under development but in a state where some customers may find them useful. If not used these features should be disabled to reduce attack surface and risk that may be present in features not considered production ready.'
  desc  'rationale', ''
  desc  'check', "
    From the Cloud Director provider interface, go to Administration >> Settings >> Feature Flags.

    Review the available feature flags and their state.

    If any feature flags are enabled and no actively used, this is a finding.
  "
  desc 'fix', "
    From the Cloud Director provider interface, go to Administration >> Settings >> Feature Flags.

    Select the target feature flag and click Disable.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CDAP-10-000133'
  tag rid: 'SV-CDAP-10-000133'
  tag stig_id: 'CDAP-10-000133'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  approvedFlags = input('approvedFeatureFlags')
  result = http("https://#{input('vcdURL')}/cloudapi/1.0.0/featureFlags",
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
    features = JSON.parse(result.body)
    features['values'].each do |feature|
      describe "Feature #{feature['displayName']}" do
        subject { feature['displayName'] }
        it { should be_in approvedFlags }
      end
    end
  end
end
