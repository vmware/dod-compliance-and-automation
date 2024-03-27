control 'VRAA-8X-000074' do
  title 'The VMware Aria Automation ingress controller must set the log level to capture sufficient events.'
  desc  "
    Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. The web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the web server must be able to facilitate these changes.

    The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events. If these events are not logged at a minimum, any type of forensic investigation would be missing pertinent information needed to replay what occurred.

    Note: Elevated logging levels must be applied only during troubleshooting as these levels can reduce performance and increase the verbose log messages. After you complete troubleshooting using elevated logging levels, the log level must be reset to INFO.
  "
  desc  'rationale', ''
  desc  'check', "
    From the command line interface, run the following command:

    # kubectl -n ingress describe cm ingress-ctl-traefik | grep 'logLevel'

    Expected result:

    logLevel = \"INFO\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/charts/ingress-ctl/templates/configmap.yaml

    Find and configure the following line:

    logLevel = \"INFO\"

    Note: If VMware Aria Automation is clustered this file should be updated on all nodes.

    From the command line interface, run the following command:

    # /opt/scripts/deploy.sh

    Note: This is a service impacting command and will re-instantiate the Kubernetes deployments.  This will also perform the action on all nodes if VMware Aria Automation is clustered.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-AS-000168'
  tag gid: 'V-VRAA-8X-000074'
  tag rid: 'SV-VRAA-8X-000074'
  tag stig_id: 'VRAA-8X-000074'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe command('kubectl -n ingress describe cm ingress-ctl-traefik | grep "logLevel"') do
    its('stdout.strip') { should cmp 'logLevel = "INFO"' }
  end
end
