control 'CNTR-K8-003170' do
  title 'The Kubernetes Kubelet certificate authority must be owned by root.'
  desc 'The Kubernetes kube proxy kubeconfig contain the argument and setting for the Control Planes. These settings contain network rules for restricting network communication between pods, clusters, and networks. If these files can be changed, data traversing between the Kubernetes Control Panel components would be compromised. Many of the security settings within the document are implemented through this file.'
  desc 'check', "Change to the /etc/sysconfig/ directory on the Kubernetes Control Plane.
Review the ownership of the Kubernetes  client-ca-file by using the command:
more kubelet
--client-ca-file argument
Note certificate location

Review the ownership of the Kubernetes client-ca-file by using the command:
stat -c   %U:%G &lt;location from --client-ca-file argument&gt;| grep -v root:root

If the command returns any non root:root file permissions, this is a finding."
  desc 'fix', "Change the permissions of the Kube Proxy to \"root\" by executing the command:

chown root:root &lt;location from kubeconfig&gt;."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242450'
  tag rid: 'SV-242450r864022_rule'
  tag stig_id: 'CNTR-K8-003170'
  tag fix_id: 'F-45683r712705_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  kubelet_conf_path = input('kubelet_conf_path')

  client_ca_file = if kubelet_conf_path
                     kubelet_config_file(kubelet_conf_path).params.dig('authentication', 'x509', 'clientCAFile')
                   else
                     kubelet_config_file.params.dig('authentication', 'x509', 'clientCAFile')
                   end

  describe.one do
    describe kubelet do
      its('client_ca_file') { should_not be_nil }
      its('client_ca_file') { should be_owned_by('root') }
      its('client_ca_file') { should be_grouped_into('root') }
    end
    describe file(client_ca_file) do
      it { should be_owned_by('root') }
      it { should be_grouped_into('root') }
    end
  end
end
