control 'CFAP-5X-000002' do
  title 'The SDDC Manager must be deployed with FIPS mode enabled.'
  desc  "
    Remote management access is accomplished by leveraging common communication protocols and establishing a remote connection to the application server via a network for the purposes of managing the application server. If cryptography is not used, then the session data traversing the remote connection could be intercepted and compromised.

    Types of management interfaces utilized by an application server include web-based HTTPS interfaces as well as command line-based management interfaces.
  "
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager UI, navigate to Developer Center >> API Explorer.

    Find the \"FIPS mode details\" section and expand the GET section and click \"Execute\".

    or

    From a command prompt, run the following command:

    $ curl 'https://sddc-manager.sfo01.rainpole.local/v1/system/security/fips' -i -X GET -H 'Authorization: Bearer etYWRta....'

    Note: The SDDC Manager URL and bearer token must be replaced in the example.

    Review the response to verify FIPS mode is enabled.

    If FIPS mode is not enabled, this is a finding.
  "
  desc 'fix', 'FIPS mode must be enabled at time of deployment and cannot be enabled post deployment.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag satisfies: ['SRG-APP-000015-AS-000010', 'SRG-APP-000179-AS-000129', 'SRG-APP-000224-AS-000152', 'SRG-APP-000439-AS-000155', 'SRG-APP-000439-AS-000274', 'SRG-APP-000440-AS-000167', 'SRG-APP-000441-AS-000258', 'SRG-APP-000442-AS-000259']
  tag gid: 'V-CFAP-5X-000002'
  tag rid: 'SV-CFAP-5X-000002'
  tag stig_id: 'CFAP-5X-000002'
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-001188', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'IA-7', 'SC-23 (3)', 'SC-8', 'SC-8 (1)', 'SC-8 (2)']

  result = http("https://#{input('sddcManager')}/v1/system/security/fips",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'Authorization' => "#{input('bearerToken')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('enabled') { should cmp 'true' }
    end
  end
end
