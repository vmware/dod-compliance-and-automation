control 'CNTR-K8-000850' do
  title 'Kubernetes Kubelet must deny hostname override.'
  desc 'Kubernetes allows for the overriding of hostnames. Allowing this feature to be implemented within the kubelets may break the TLS setup between the kubelet service and the API server. This setting also can make it difficult to associate logs with nodes if security analytics needs to take place. The better practice is to setup nodes with resolvable FQDNs and avoid overriding the hostnames.'
  desc 'check', "On the Kubernetes Control Plane and Worker nodes, run the command:
ps -ef | grep kubelet

Check the config file (path identified by: --config):

Change to the directory identified by --config (example /etc/sysconfig/) run the command:
grep -i hostname-override kubelet

If any of the nodes have the setting \"hostname-override\" present, this is a finding."
  desc 'fix', "Edit the kubelet file on each node under the --config directory and  remove the hostname-override setting.

Reset Kubelet service using the following command:
service kubelet restart"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000290'
  tag gid: 'V-242404'
  tag rid: 'SV-242404r863980_rule'
  tag stig_id: 'CNTR-K8-000850'
  tag fix_id: 'F-45637r863810_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  describe kubelet do
    its('hostname-override') { should be_nil }
  end
end
