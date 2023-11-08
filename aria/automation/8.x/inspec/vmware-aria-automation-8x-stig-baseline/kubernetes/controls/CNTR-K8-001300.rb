control 'CNTR-K8-001300' do
  title 'Kubernetes Kubelet must not disable timeouts.'
  desc 'Idle connections from the Kubelet can be used by unauthorized users to perform malicious activity to the nodes, pods, containers, and cluster within the Kubernetes Control Plane. Setting the streaming connection idle timeout defines the maximum time an idle session is permitted prior to disconnect. Setting the value to "0" never disconnects any idle sessions. Idle timeouts must never be set to "0" and should be defined at "5m" (the default is 4hr).'
  desc 'check', "On the Kubernetes Control Plane, run the command:
ps -ef | grep kubelet
Check the config file (path identified by: --config):

Change to the directory identified by --config (example /etc/sysconfig/) run the command:
grep -i streaming-connection-idle-timeout kubelet

If the setting streaming-connection-idle-timeout is set to &lt; \"5m\" or the parameter is not configured in the Kubernetes Kubelet, this is a finding."
  desc 'fix', "Edit the Kubernetes Kubelet file in the --config directory on the Kubernetes Control Plane:

Set the argument \"--streaming-connection-idle-timeout\" to a value of \"5m\".

Reset Kubelet service using the following command:
service kubelet restart"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000190-CTR-000500'
  tag gid: 'V-245541'
  tag rid: 'SV-245541r864032_rule'
  tag stig_id: 'CNTR-K8-001300'
  tag fix_id: 'F-48771r863941_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  kubelet_conf_path = input('kubelet_conf_path')

  if kubelet_conf_path
    describe.one do
      describe kubelet do
        its('streaming-connection-idle-timeout') { should_not be_nil }
        its('streaming-connection-idle-timeout') { should cmp >= '5m' }
      end
      describe kubelet_config_file(kubelet_conf_path) do
        its(['streamingConnectionIdleTimeout']) { should cmp >= '5m' }
      end
    end
  else
    describe.one do
      describe kubelet do
        its('streaming-connection-idle-timeout') { should_not be_nil }
        its('streaming-connection-idle-timeout') { should cmp >= '5m' }
      end
      describe kubelet_config_file do
        its(['streamingConnectionIdleTimeout']) { should cmp >= '5m' }
      end
    end
  end
end
