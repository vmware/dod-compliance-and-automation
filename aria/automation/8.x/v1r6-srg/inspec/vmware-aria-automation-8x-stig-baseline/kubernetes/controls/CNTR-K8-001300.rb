control 'CNTR-K8-001300' do
  title 'Kubernetes Kubelet must not disable timeouts.'
  desc 'Idle connections from the Kubelet can be used by unauthorized users to perform malicious activity to the nodes, pods, containers, and cluster within the Kubernetes Control Plane. Setting the streamingConnectionIdleTimeout defines the maximum time an idle session is permitted prior to disconnect. Setting the value to "0" never disconnects any idle sessions. Idle timeouts must never be set to "0" and should be defined at "5m" (the default is 4hr).'
  desc 'check', 'On the Control Plane, run the command:
ps -ef | grep kubelet

If the "--streaming-connection-idle-timeout" option exists, this is a finding.

Note the path to the config file (identified by --config).

Run the command:
grep -i streamingConnectionIdleTimeout <path_to_config_file>

If the setting "streamingConnectionIdleTimeout" is set to less than "5m" or is not configured, this is a finding.'
  desc 'fix', 'On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "--streaming-connection-idle-timeout" option if present.

Note the path to the config file (identified by --config).

Edit the Kubernetes Kubelet file in the --config directory on the Kubernetes Control Plane:

Set the argument "streamingConnectionIdleTimeout" to a value of "5m".

Reset the kubelet service using the following command:
service kubelet restart'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-48816r918208_chk'
  tag severity: 'medium'
  tag gid: 'V-245541'
  tag rid: 'SV-245541r918210_rule'
  tag stig_id: 'CNTR-K8-001300'
  tag gtitle: 'SRG-APP-000190-CTR-000500'
  tag fix_id: 'F-48771r918209_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  if kube_apiserver.exist?
    kubelet_process = input('kubelet_process')
    kubelet_conf_path = input('kubelet_conf_path')

    describe kubelet(kubelet_process) do
      its('streaming-connection-idle-timeout') { should be nil }
    end
    if kubelet_conf_path
      describe kubelet_config_file(kubelet_conf_path) do
        its(['streamingConnectionIdleTimeout']) { should cmp >= '5m' }
      end
    else
      describe kubelet_config_file do
        its(['streamingConnectionIdleTimeout']) { should cmp >= '5m' }
      end
    end
  else
    impact 0.0
    describe 'This control does not apply to worker nodes so this is not applicable.' do
      skip 'This control does not apply to worker nodes so this is not applicable.'
    end
  end
end
