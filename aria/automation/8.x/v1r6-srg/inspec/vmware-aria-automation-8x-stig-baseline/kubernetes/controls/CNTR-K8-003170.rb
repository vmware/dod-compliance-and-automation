control 'CNTR-K8-003170' do
  title 'The Kubernetes Kubelet certificate authority must be owned by root.'
  desc 'The Kubernetes kube proxy kubeconfig contain the argument and setting for the Control Planes. These settings contain network rules for restricting network communication between pods, clusters, and networks. If these files can be changed, data traversing between the Kubernetes Control Panel components would be compromised. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'On the Control Plane, run the command:
ps -ef | grep kubelet

If the "client-ca-file" option exists, this is a finding.

Note the path to the config file (identified by --config).

Run the command:
grep -i clientCAFile <path_to_config_file>

Note the path to the client ca file.

Run the command:
stat -c %U:%G <path_to_client_ca_file>

If the command returns any non root:root file permissions, this is a finding.'
  desc 'fix', 'On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "client-ca-file" option.

Note the path to the config file (identified by --config).

Run the command:
grep -i clientCAFile <path_to_config_file>

Note the path to the client ca file.

Run the command:
chown root:root <path_to_client_ca_file>'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45725r918194_chk'
  tag severity: 'medium'
  tag gid: 'V-242450'
  tag rid: 'SV-242450r918196_rule'
  tag stig_id: 'CNTR-K8-003170'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45683r918195_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if kube_apiserver.exist?
    kubelet_process = input('kubelet_process')
    kubelet_conf_path = input('kubelet_conf_path')

    client_ca_file = if kubelet_conf_path
                       kubelet_config_file(kubelet_conf_path).params.dig('authentication', 'x509', 'clientCAFile')
                     else
                       kubelet_config_file.params.dig('authentication', 'x509', 'clientCAFile')
                     end

    describe kubelet(kubelet_process) do
      its('client-ca-file') { should be nil }
    end
    describe file(client_ca_file) do
      it { should be_owned_by('root') }
      it { should be_grouped_into('root') }
    end
  else
    impact 0.0
    describe 'This control does not apply to worker nodes so this is not applicable.' do
      skip 'This control does not apply to worker nodes so this is not applicable.'
    end
  end
end
