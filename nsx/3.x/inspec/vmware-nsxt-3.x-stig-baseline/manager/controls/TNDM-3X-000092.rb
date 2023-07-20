control 'TNDM-3X-000092' do
  title 'The NSX-T Manager must integrate with either VMware Identity Manager (vIDM) or VMware Workspace ONE Access.'
  desc  "
    Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device.

    Use VMware Identity Manager or Workspace ONE configured to meet DoD requirements for authentication, authorization, and access control. This does not require an additional license. Configuration details of this product are not in scope beyond this requirement. Ensure the VMware Workspace ONE Access/VMware Identity Manager acts as a broker to different identity stores and providers, including Active Directory and SAML.

    Two supplements are included with the VMware NSX-T STIG package that provide guidance from the vendor for configuration of VMware Identity Manager and VMware Workspace ONE Access.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX-T Manager web interface, go to System >> Users and Roles >> VMware Identity Manager.

    If the VMware Identity Manager integration is not enabled, this is a finding.

    If the user is not redirected to VMware Identity Manager or Workspace ONE Access when attempting to log in to the NSX-T Manager web interface and prompted to select a certificate and enter a PIN, this is a finding.
  "
  desc 'fix', "
    To configure NSX-T to integrate with VMware Identity Manager or Workspace ONE Access as the authentication source, do the following:

    From the NSX-T Manager web interface, go to System >> Users and Roles >> VMware Identity Manager and click \"Edit\".

    If using an external load balancer for the NSX-T Management cluster, enable \"External Load Balancer Integration\". If using a cluster VIP, leave this disabled.

    Click the toggle button to enable \"VMware Identity Manager Integration\".

    Enter the VMware Identity Manager or Workspace ONE Access appliance name, OAuth Client ID, OAuth Client Secret, and certificate thumbprint as provided by the administrators.

    Enter the NSX Appliance FQDN. For a cluster, enter the load balancer FQDN or cluster VIP FQDN.

    Click \"Save\", import users and groups, and then assign them roles.

    Ensure the VMware Identity Manager administrators have configured the certificate authentication adapter to provide two-factor authentication.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag satisfies: ['SRG-APP-000177-NDM-000263', 'SRG-APP-000149-NDM-000247', 'SRG-APP-000080-NDM-000220']
  tag gid: 'V-251789'
  tag rid: 'SV-251789r819722_rule'
  tag stig_id: 'TNDM-3X-000092'
  tag fix_id: 'F-55203r819721_fix'
  tag cci: ['CCI-000370', 'CCI-000187', 'CCI-000166', 'CCI-000366', 'CCI-000764', 'CCI-000765']
  tag nist: ['CM-6 (1)', 'IA-5 (2) (a) (2)', 'AU-10', 'CM-6 b', 'IA-2', 'IA-2 (1)']

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
