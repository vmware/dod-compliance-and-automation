control 'VLMA-8X-000004' do
  title 'VMware Aria Suite Lifecycle must configure authentication when a proxy server is specified.'
  desc  'Application architecture may sometimes require a configuration where an application server is placed behind a web proxy or an application gateway, or communicates directly with another application server. In those instances, the application server hosting the service/application is considered the server. The application server, proxy or application gateway consuming the hosted service is considered a client. Authentication is accomplished via the use of certificates and protocols such as TLS mutual authentication. Authentication must be performed when the proxy is exposed to an untrusted network or when data protection requirements specified in the system security plan mandate the need to establish the identity of the connecting application server, proxy or application gateway.'
  desc  'rationale', ''
  desc  'check', "
    If VMware Aria Suite Lifecycle is not configured to use a proxy, this is Not Applicable.

    Log in to the VMware Aria Suite Lifecycle management interface.

    Select \"Lifecycle Operations\" >> Settings >> Proxy to view the Proxy configuration.

    If the Proxy is configured and no credential is selected, this is a finding.
  "
  desc  'fix', "
    Log in to the VMware Aria Suite Lifecycle management interface.

    Select \"Lifecycle Operations\" >> Settings >> Proxy to view the Proxy configuration.

    If the Proxy is not used or is not needed remove the check box next to \"Configure Proxy\".

    If you are enabling Proxy, enter the Server and Port, then select an existing credential.

    Click Save.

    Note: If a credential for the Proxy does not already exist one will need to be created first by going to Locker >> Passwords.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-AS-000147'
  tag gid: 'V-VLMA-8X-000004'
  tag rid: 'SV-VLMA-8X-000004'
  tag stig_id: 'VLMA-8X-000004'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  cred = Base64.encode64("#{input('username')}:#{input('password')}")

  response = http("https://#{input('hostname')}/lcm/lcops/api/v2/settings/proxies",
      method: 'GET',
      headers: {
      'Content-Type' => 'application/json',
      'Accept' => 'application/json',
      'Authorization' => "Basic #{cred}",
      },
      ssl_verify: false)

  describe response do
    its('status') { should cmp 200 }
  end

  unless response.status != 200
    result = JSON.parse(response.body)

    if result['proxyEnabled'].eql?(false)
      impact 0.0
      describe 'No proxies configured' do
        skip 'No proxies configured'
      end
    else
      describe result['password'] do
        it { should_not be_empty }
      end
    end
  end
end
