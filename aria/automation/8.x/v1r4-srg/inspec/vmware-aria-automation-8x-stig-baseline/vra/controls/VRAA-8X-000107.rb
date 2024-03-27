control 'VRAA-8X-000107' do
  title 'VMware Aria Automation must implement approved TLS versions.'
  desc  "
    Encryption is critical for protection of remote access sessions. If encryption is not being used for integrity, malicious users may gain the ability to modify the application server configuration. The use of cryptography for ensuring integrity of remote access sessions mitigates that risk.

    Application servers utilize a web management interface and scripted commands when allowing remote access. Web access requires the use of TLS and scripted access requires using some form of approved cryptography.

    FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL and TLS versions must be disabled.

    NIST SP 800-52 specifies the preferred configurations for government systems.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the minimum TLS version in use by running the following command:

    # kubectl -n ingress describe cm ingress-ctl-traefik | grep \"minVersion\"

    Example output:

    minVersion = \"VersionTLS12\"

    If any version besides TLSv1.2 or TLSv1.3 is returned, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/charts/ingress-ctl/values.yaml

    Under the \"ssl\" heading, add or configure the following line:

    tlsMinVersion: VersionTLS12

    Note: If VMware Aria Automation is clustered this file should be updated on all nodes.

    From the command line interface, run the following command:

    # /opt/scripts/deploy.sh

    Note: This is a service impacting command and will re-instantiate the Kubernetes deployments.  This will also perform the action on all nodes if VMware Aria Automation is clustered.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-AS-000155'
  tag satisfies: ['SRG-APP-000439-AS-000274', 'SRG-APP-000440-AS-000167', 'SRG-APP-000442-AS-000259']
  tag gid: 'V-VRAA-8X-000107'
  tag rid: 'SV-VRAA-8X-000107'
  tag stig_id: 'VRAA-8X-000107'
  tag cci: ['CCI-002418', 'CCI-002421', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (1)', 'SC-8 (2)']

  describe command('kubectl -n ingress describe cm ingress-ctl-traefik | grep "minVersion"') do
    its('stdout.strip') { should cmp 'minVersion = "VersionTLS12"' }
  end
end
