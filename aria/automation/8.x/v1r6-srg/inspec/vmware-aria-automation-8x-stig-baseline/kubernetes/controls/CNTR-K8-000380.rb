control 'CNTR-K8-000380' do
  title 'The Kubernetes kubelet must enable explicit authorization.'
  desc 'Kubelet is the primary agent on each node. The API server communicates with each kubelet to perform tasks such as starting/stopping pods. By default, kubelets allow all authenticated requests, even anonymous ones, without requiring any authorization checks from the API server. This default behavior bypasses any authorization controls put in place to limit what users may perform within the Kubernetes cluster. To change this behavior, the default setting of AlwaysAllow for the authorization mode must be set to "Webhook".'
  desc 'check', 'On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

If the "--authorization-mode" option exists, this is a finding.

Note the path to the config file (identified by --config).

Inspect the content of the config file:
Locate the "authorization" section. If the field "mode" does not exist or is not set to "Webhook", this is a finding.'
  desc 'fix', 'On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "--authorization-mode" option if present.

Note the path to the config file (identified by --config).

Edit the config file:
In the "authorization" section, set "mode" to "Webhook".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45667r918153_chk'
  tag severity: 'high'
  tag gid: 'V-242392'
  tag rid: 'SV-242392r918155_rule'
  tag stig_id: 'CNTR-K8-000380'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45625r918154_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  kubelet_process = input('kubelet_process')
  kubelet_conf_path = input('kubelet_conf_path')

  describe kubelet(kubelet_process) do
    its('authorization-mode') { should be nil }
  end
  if kubelet_conf_path
    describe kubelet_config_file(kubelet_conf_path) do
      its(['authorization', 'mode']) { should cmp 'Webhook' }
    end
  else
    describe kubelet_config_file do
      its(['authorization', 'mode']) { should cmp 'Webhook' }
    end
  end
end
