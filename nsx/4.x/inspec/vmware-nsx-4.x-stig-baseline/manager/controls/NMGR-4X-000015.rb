control 'NMGR-4X-000015' do
  title 'The NSX Manager must be configured to integrate with an identity provider that supports Multi-factor authentication (MFA).'
  desc  "
    This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

    Multi-factor authentication (MFA) is when two or more factors are used to confirm the identity of an individual who is requesting access to digital information resources. Valid factors include something the individual knows (e.g., username and password), something the individual has (e.g., a smartcard or token), or something the individual is (e.g., a fingerprint or biometric). Legacy information system environments only use a single factor for authentication, typically a username and password combination. Although two pieces of data are used in a username and password combination, this is still considered single factor because an attacker can obtain access simply by learning what the user knows. Common attacks against single-factor authentication are attacks on user passwords. These attacks include brute force password guessing, password spraying, and password credential stuffing. MFA, along with strong user account hygiene, helps mitigate against the threat of having account passwords discovered by an attacker. Even in the event of a password compromise, with MFA implemented and required for interactive login, the attacker still needs to acquire something the user has or replicate a piece of user’s biometric digital presence.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to System >> Users and Roles >> VMware Identity Manager.

    If the VMware Identity Manager integration is not enabled, this is a finding.

    If the user is not redirected to VMware Identity Manager or Workspace ONE Access when attempting to log in to the NSX-T Manager web interface and prompted to select a certificate and enter a PIN, this is a finding.
  "
  desc 'fix', "
    To configure NSX to integrate with VMware Identity Manager or Workspace ONE Access as the authentication source, do the following:

    From the NSX Manager web interface, go to System >> Users and Roles >> VMware Identity Manager and click \"Edit\".

    If using an external load balancer for the NSX Management cluster, enable \"External Load Balancer Integration\". If using a cluster VIP, leave this disabled.

    Click the toggle button to enable \"VMware Identity Manager Integration\".

    Enter the VMware Identity Manager or Workspace ONE Access appliance name, OAuth Client ID, OAuth Client Secret, and certificate thumbprint as provided by the administrators.

    Enter the NSX Appliance FQDN. For a cluster, enter the load balancer FQDN or cluster VIP FQDN.

    Click \"Save\", import users and groups, and then assign them roles.

    Ensure the VMware Identity Manager administrators have configured the certificate authentication adapter to provide two-factor authentication.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag satisfies: ['SRG-APP-000149-NDM-000247', 'SRG-APP-000516-NDM-000336']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'NMGR-4X-000015'
  tag cci: ['CCI-000166', 'CCI-000366', 'CCI-000765']
  tag nist: ['AU-10', 'CM-6 b', 'IA-2 (1)']

  result = http("https://#{input('nsxManager')}/api/v1/node/aaa/providers/vidm",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('vidm_enable') { should cmp 'true' }
    end
  end
  describe 'This check is a manual or policy based check' do
    skip 'Validate that certificate based authentication is configured in vIDM.'
  end
end
