control 'VRAA-8X-000014' do
  title 'The VMware Aria Automation ingress controller must use cryptography to protect remote sessions.'
  desc  'Data exchanged during the remote session between the user and a web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.'
  desc  'rationale', ''
  desc  'check', "
    From the command line interface, run the following command:

    # kubectl -n ingress describe cm ingress-ctl-traefik | grep '\\[entryPoints.https\\]'

    Expected result:

    [entryPoints.https]

    If the output does not match the expected result, this is a finding.

    The presence of the https entry point indicates SSL is enabled in the ingress controller.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/charts/ingress-ctl/values.yaml

    Add or configure the following line:

    Under the ssl: section

    ssl:
      enabled: true

    Note: If VMware Aria Automation is clustered this file should be updated on all nodes.

    From the command line interface, run the following command:

    # /opt/scripts/deploy.sh

    Note: This is a service impacting command and will re-instantiate the Kubernetes deployments.  This will also perform the action on all nodes if VMware Aria Automation is clustered.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag gid: 'V-VRAA-8X-000014'
  tag rid: 'SV-VRAA-8X-000014'
  tag stig_id: 'VRAA-8X-000014'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  describe command('kubectl -n ingress describe cm ingress-ctl-traefik | grep "\[entryPoints.https\]"') do
    its('stdout.strip') { should cmp '[entryPoints.https]' }
  end
end
