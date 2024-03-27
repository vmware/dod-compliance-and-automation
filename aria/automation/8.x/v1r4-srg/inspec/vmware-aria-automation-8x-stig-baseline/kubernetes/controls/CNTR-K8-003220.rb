control 'CNTR-K8-003220' do
  title 'The Kubernetes kubeadm.conf must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes kubeadm.conf contains sensitive information regarding the cluster nodes configuration. If this file can be modified, the Kubernetes Platform Plane would be degraded or compromised for malicious intent. Many of the security settings within the document are implemented through this file.'
  desc 'check', "Review the kubeadm.conf file :

Get the path for kubeadm.conf by running:
systemctl status kubelet

Note the configuration file installed by the kubeadm is written to
(Default Location: /etc/systemd/system/kubelet.service.d/10-kubeadm.conf)
stat -c %a  &lt;kubeadm.conf path&gt;

If the file has permissions more permissive than \"644\", this is a finding."
  desc 'fix', "Change the permissions of kubeadm.conf to \"644\" by executing the command:

chmod 644 &lt;kubeadm.conf path&gt;"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag gid: 'V-242455'
  tag rid: 'SV-242455r754822_rule'
  tag stig_id: 'CNTR-K8-003220'
  tag fix_id: 'F-45688r754821_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  kubeadm_conf_path = input('kubeadm_conf_path')

  if file(kubeadm_conf_path).exist?
    describe file(kubeadm_conf_path) do
      it { should_not be_more_permissive_than('0644') }
    end
  else
    describe "Kubeadm file #{kubeadm_conf_path} not found on target." do
      skip "Kubeadm file #{kubeadm_conf_path} not found on target."
    end
  end
end
