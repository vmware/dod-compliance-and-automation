control 'CNTR-K8-000850' do
  title 'Kubernetes Kubelet must deny hostname override.'
  desc 'Kubernetes allows for the overriding of hostnames. Allowing this feature to be implemented within the kubelets may break the TLS setup between the kubelet service and the API server. This setting also can make it difficult to associate logs with nodes if security analytics needs to take place. The better practice is to setup nodes with resolvable FQDNs and avoid overriding the hostnames.'
  desc 'check', 'On the Control Plane and Worker nodes, run the command:
ps -ef | grep kubelet

If the option "--hostname-override" is present, this is a finding.'
  desc 'fix', 'Run the command:
systemctl status kubelet.
Note the path to the drop-in file.

Determine the path to the environment file(s) with the command:
grep -i EnvironmentFile <path_to_drop_in_file>.

Remove the "--hostname-override" option from any environment file where it is present.

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45679r918165_chk'
  tag severity: 'medium'
  tag gid: 'V-242404'
  tag rid: 'SV-242404r918167_rule'
  tag stig_id: 'CNTR-K8-000850'
  tag gtitle: 'SRG-APP-000133-CTR-000290'
  tag fix_id: 'F-45637r918166_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  kubelet_process = input('kubelet_process')

  describe kubelet(kubelet_process) do
    its('hostname-override') { should be_nil }
  end
end
