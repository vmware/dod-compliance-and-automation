control 'VRAA-8X-000046' do
  title 'The VMware Aria Automation RabbitMQ service must disable any unneeded plugins.'
  desc  "
    Application servers provide a myriad of differing processes, features and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system.

    Application servers must provide the capability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance, for example, disabling dynamic JSP reloading on production application servers as a best practice.
  "
  desc  'rationale', ''
  desc  'check', "
    From the command line interface, run the following command:

    # kubectl -n prelude describe cm rabbitmq-ha | sed -n '/enabled_plugins:/,/]\\./p'

    Expected result:

    enabled_plugins:
    ----
    [

      rabbitmq_consistent_hash_exchange,
      rabbitmq_federation,
      rabbitmq_federation_management,
      rabbitmq_management,
      rabbitmq_peer_discovery_k8s,
      rabbitmq_shovel,
      rabbitmq_shovel_management
    ].

    If the output does not match the expected result and any additional plugins are enabled, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/charts/rabbitmq-ha/values.yaml

    For each plugin that was unexpectedly loaded in the check, find the section for that plugin and set it to \"enabled: false\" and also comment out any configuration for that plugin.

    Note: If VMware Aria Automation is clustered this file should be updated on all nodes.

    From the command line interface, run the following command:

    # /opt/scripts/deploy.sh

    Note: This is a service impacting command and will re-instantiate the Kubernetes deployments.  This will also perform the action on all nodes if VMware Aria Automation is clustered.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRAA-8X-000046'
  tag rid: 'SV-VRAA-8X-000046'
  tag stig_id: 'VRAA-8X-000046'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  expected_result = "enabled_plugins: ---- [
    rabbitmq_consistent_hash_exchange,
    rabbitmq_federation,
    rabbitmq_federation_management,
    rabbitmq_management,
    rabbitmq_peer_discovery_k8s,
    rabbitmq_shovel, rabbitmq_shovel_management ].".gsub!(/\s/, '')

  result = command('kubectl -n prelude describe cm rabbitmq-ha | sed -n "/enabled_plugins:/,/]\./p"')

  describe 'Checking Enabled RabbitMQ plugins' do
    subject { result.stdout.strip.gsub!(/\s/, '') }
    it { should cmp expected_result }
  end
end
