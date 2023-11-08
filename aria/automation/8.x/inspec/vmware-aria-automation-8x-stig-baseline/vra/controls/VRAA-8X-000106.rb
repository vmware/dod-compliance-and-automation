control 'VRAA-8X-000106' do
  title 'The VMware Aria Automation ingress controller must be tuned to handle the operational requirements of the application.'
  desc  'A Denial of Service (DoS) can occur when the web server is so overwhelmed that it can no longer respond to additional requests. A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To help avoid a DoS, the web server must be tuned to handle the expected traffic for the hosted applications.'
  desc  'rationale', ''
  desc  'check', "
    From the command line interface, run the following command:

    # kubectl -n ingress describe pod ingress-ctl-traefik | grep -i limits -A 2 | grep cpu

    Expected Result:

          cpu:     500m

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/charts/ingress-ctl/values.yaml

    Add or configure the following line:

    cpuLimit: 500m

    Note: If VMware Aria Automation is clustered this file should be updated on all nodes.

    From the command line interface, run the following command:

    # /opt/scripts/deploy.sh

    Note: This is a service impacting command and will re-instantiate the Kubernetes deployments.  This will also perform the action on all nodes if VMware Aria Automation is clustered.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag gid: 'V-VRAA-8X-000106'
  tag rid: 'SV-VRAA-8X-000106'
  tag stig_id: 'VRAA-8X-000106'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

  result = command('kubectl -n ingress describe pod ingress-ctl-traefik | grep -i limits -A 2 | grep cpu')

  describe 'Checking CPU limits' do
    subject { result.stdout.gsub(/\s/, '') }
    it { should cmp 'cpu:500m' }
  end
end
