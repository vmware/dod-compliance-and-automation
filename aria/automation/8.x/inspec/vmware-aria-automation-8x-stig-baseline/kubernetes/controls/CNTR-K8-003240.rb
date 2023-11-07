control 'CNTR-K8-003240' do
  title 'The Kubernetes kubelet config must be owned by root.'
  desc 'The Kubernetes kubelet agent registers nodes with the API Server and performs health checks to containers within pods. If this file can be modified, the information system would be unaware of pod or container degradation.'
  desc 'check', "Review the Kubernetes Kubeadm kubelet conf file by using the command:

stat -c %U:%G /var/lib/kubelet/config.yaml| grep -v root:root

If the command returns any non root:root file permissions, this is a finding."
  desc 'fix', "Change the ownership of the kubelet config to \"root: root\" by executing the command:

chown root:root /var/lib/kubelet/config.yaml"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001330'
  tag gid: 'V-242457'
  tag rid: 'SV-242457r712727_rule'
  tag stig_id: 'CNTR-K8-003240'
  tag fix_id: 'F-45690r712726_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  kubelet_conf_path = input('kubelet_conf_path')

  if kubelet_conf_path
    describe.one do
      describe kubelet do
        its('config_file') { should be_owned_by('root') }
        its('config_file') { should be_grouped_into('root') }
      end
      describe file(kubelet_conf_path) do
        it { should be_owned_by('root') }
        it { should be_grouped_into('root') }
      end
    end
  else
    describe.one do
      describe kubelet do
        its('config_file') { should be_owned_by('root') }
        its('config_file') { should be_grouped_into('root') }
      end
      describe kubelet_config_file do
        it { should be_owned_by('root') }
        it { should be_grouped_into('root') }
      end
    end
  end
end
