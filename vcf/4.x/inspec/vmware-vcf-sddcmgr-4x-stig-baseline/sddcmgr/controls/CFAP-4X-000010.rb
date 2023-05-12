control 'CFAP-4X-000010' do
  title 'The SDDC Manager must be deployed with FIPS mode enabled.'
  desc  'Remote management access is accomplished by leveraging common communication protocols and establishing a remote connection to the application server via a network for the purposes of managing the application server. If cryptography is not used, then the session data traversing the remote connection could be intercepted and compromised. Types of management interfaces utilized by an application server include web-based HTTPS interfaces as well as command line-based management interfaces.'
  desc  'rationale', ''
  desc  'check', "
    If Cloud Foundation was deployed prior to 4.3, this is not applicable.

    From the SDDC Manager UI, navigate to Developer Center >> API Explorer.

    Find the \"APIs for getting FIPS mode details\" section and expand the GET section and click \"Execute\".

    or

    From a command prompt, run the following command:

    $ curl 'https://sddc-manager.sfo01.rainpole.local/v1/system/security/fips' -i -X GET -H 'Authorization: Bearer etYWRta....'

    Note: The SDDC manager URL and bearer token must be replaced in the example.

    Review the response to verify FIPS mode is enabled.

    If FIPS mode is not enabled, this is a finding.
  "
  desc 'fix', 'FIPS mode must be enabled at time of deployment and cannot be enabled post deployment.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag gid: 'V-CFAP-4X-000010'
  tag rid: 'SV-CFAP-4X-000010'
  tag stig_id: 'CFAP-4X-000010'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

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
