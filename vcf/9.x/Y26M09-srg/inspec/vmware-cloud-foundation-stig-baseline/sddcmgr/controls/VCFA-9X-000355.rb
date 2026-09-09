control 'VCFA-9X-000355' do
  title 'VMware Cloud Foundation SDDC Manager must disable basic authentication.'
  desc  'Basic authentication is passed over the network in clear text as a base64 encoded string that is easily reversible and is not considered secure. Even though it is over HTTPS/TLS, which offers more protection to eavesdropping, it should not be used.'
  desc  'rationale', ''
  desc  'check', "
    The basic authentication configuration can only be viewed from the SDDC Manager API.

    To view the configuration, first obtain an API token by doing the following:

    From the SDDC Manager UI, go to Developer Center >> API Explorer.

    Locate the \"Tokens\" section and expand \"POST\".

    In the body value text box enter the credentials to create an API token with, for example:

    {
    \t\"username\": \"replace with username\",
    \t\"password\": \"replace with password\"
    }

    Click \"Execute\" and copy the \"accessToken\" from the response.

    From a command prompt, run the following:

    $ curl 'https://sddc-manager.sfo01.rainpole.local/v1/sddc-manager' -i -k -X GET -H 'Authorization: Bearer etYWRta....'

    Note: The SDDC Manager URL and bearer token must be replaced in the example.

    Review the response and verify in the \"basicAuthDetails\" section that \"status\" is set to \"DISABLED\".

    If basic authentication is enabled, this is a finding.
  "
  desc 'fix', "
    Reuse or obtain a new API token following the steps provided in the check text.

    From a command prompt, run the following:

    # curl 'https://sddc-manager.sfo01.rainpole.local/v1/sddc-manager' -i -k -H 'Authorization: Bearer etYWRta....' -H 'Content-Type: application/json' -X PATCH --data '{\"basicAuthSpec\": {\"status\" : \"DISABLE\"}}'

    Note: The SDDC Manager URL and bearer token must be replaced in the example.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000355'
  tag rid: 'SV-VCFA-9X-000355'
  tag stig_id: 'VCFA-9X-000355'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('sddcmgr_url')}/v1/sddc-manager",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'Authorization' => "Bearer #{input('sddcmgr_sessionToken')}"
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
