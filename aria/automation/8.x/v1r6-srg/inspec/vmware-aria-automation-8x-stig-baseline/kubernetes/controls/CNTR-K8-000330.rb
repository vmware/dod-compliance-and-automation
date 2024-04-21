control 'CNTR-K8-000330' do
  title 'The Kubernetes Kubelet must have the "readOnlyPort" flag disabled.'
  desc 'Kubelet serves a small REST API with read access to port 10255. The read-only port for Kubernetes provides no authentication or authorization security control. Providing unrestricted access on port 10255 exposes Kubernetes pods and containers to malicious attacks or compromise. Port 10255 is deprecated and should be disabled.'
  desc 'check', 'On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

If the "--read-only-port" option exists, this is a finding.

Note the path to the config file (identified by --config).

Run the command:
grep -i readOnlyPort <path_to_config_file>

If the setting "readOnlyPort" exists and is not set to "0", this is a finding.'
  desc 'fix', 'On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "--read-only-port" option if present.

Note the path to the config file (identified by --config).

Edit the config file:
Set "readOnlyPort" to "0" or remove the setting.

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45662r918147_chk'
  tag severity: 'high'
  tag gid: 'V-242387'
  tag rid: 'SV-242387r918149_rule'
  tag stig_id: 'CNTR-K8-000330'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45620r918148_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  kubelet_process = input('kubelet_process')
  kubelet_conf_path = input('kubelet_conf_path')

  describe kubelet(kubelet_process) do
    its('read-only-port') { should be nil }
  end
  if kubelet_conf_path
    describe.one do
      describe kubelet_config_file(kubelet_conf_path) do
        its('readOnlyPort') { should cmp 0 }
      end
      describe kubelet_config_file(kubelet_conf_path) do
        its('readOnlyPort') { should be nil }
      end
    end
  else
    describe.one do
      describe kubelet_config_file do
        its('readOnlyPort') { should cmp 0 }
      end
      describe kubelet_config_file do
        its('readOnlyPort') { should be nil }
      end
    end
  end
end
