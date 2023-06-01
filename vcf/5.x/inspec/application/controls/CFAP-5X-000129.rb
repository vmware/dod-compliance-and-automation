control 'CFAP-5X-000129' do
  title 'The SDDC Manager must disable basic authentication.'
  desc  'Basic authentication is passed over the network in clear text as a base64 encoded string that is easily reversible and is not considered secure. Even though it is over HTTPS/TLS which offers more protection to eavesdropping it should not be used.'
  desc  'rationale', ''
  desc  'check', "
    From a command prompt, run the following command:

    $ curl 'https://sddc-manager.sfo01.rainpole.local/v1/sddc-manager' -i -X GET -H 'Authorization: Bearer etYWRta....'

    Note: The SDDC Manager URL and bearer token must be replaced in the example.

    Review the response and verify in the \"basicAuthDetails\" section that \"status\" is set to \"DISABLED\".

    If basic authentication is enabled, this is a finding.
  "
  desc 'fix', "
    From a command prompt, run the following command:

    # curl 'https://sddc-manager.sfo01.rainpole.local/v1/sddc-manager' -i -H 'Authorization: Bearer etYWRta....' -H 'Content-Type: application/json' -X PATCH --data '{\"basicAuthSpec\": {\"status\" : \"DISABLE\"}}' -k

    Note: The SDDC Manager URL and bearer token must be replaced in the example.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFAP-5X-000129'
  tag rid: 'SV-CFAP-5X-000129'
  tag stig_id: 'CFAP-5X-000129'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('sddcManager')}/v1/sddc-manager",
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
      its(['basicAuthDetails', 'status']) { should cmp 'DISABLED' }
    end
  end
end
