control 'VRAA-8X-000047' do
  title 'The VMware Aria Automation ingress controller must restrict the use of unnecessary ports.'
  desc  "
    Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system.

    The web server must provide the capability to disable or deactivate network-related services that are deemed to be non-essential to the server mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability assessments.
  "
  desc  'rationale', ''
  desc  'check', "
    From the command line interface, run the following command:

    # kubectl -n ingress describe cm ingress-ctl-traefik | grep '\\[entryPoints.https\\]' -A 2 | grep 'address'

    Expected result:

      address = \":443\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/charts/ingress-ctl/values.yaml

    Find and configure the following line(s):

    service:
      nodePorts:
        http: 80
        https: 443

    Ensure https is configured to 443.

    Note: If VMware Aria Automation is clustered this file should be updated on all nodes.

    From the command line interface, run the following command:

    # /opt/scripts/deploy.sh

    Note: This is a service impacting command and will re-instantiate the Kubernetes deployments.  This will also perform the action on all nodes if VMware Aria Automation is clustered.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag gid: 'V-VRAA-8X-000047'
  tag rid: 'SV-VRAA-8X-000047'
  tag stig_id: 'VRAA-8X-000047'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  describe command('kubectl -n ingress describe cm ingress-ctl-traefik | grep "\[entryPoints.https\]" -A 2 | grep "address"') do
    its('stdout.strip') { should cmp 'address = ":443"' }
  end
end
