control 'CNTR-K8-000890' do
  title 'The Kubernetes kubelet configuration files must have file permissions set to 644 or more restrictive.'
  desc 'The kubelet configuration file contains the runtime configuration of the kubelet service. If an attacker can gain access to this file, changes can be made to open vulnerabilities and bypass user authorizations inherit within Kubernetes with RBAC implemented.'
  desc 'check', "On the Control Plane and worker nodes, change to the /etc/kubernetes/manifest directory. Run the command:
ls -l kubelet

Each kubelet configuration file must have permissions of \"644\" or more restrictive.

If any kubelet configuration file is less restrictive than \"644\", this is a finding."
  desc 'fix', "On the Control Plane, change to the /etc/kubernetes/manifest directory. Run the command:
chmod 644 kubelet

To verify the change took place, run the command:
ls -l kubelet

The kubelet file should now have the permissions of \"644\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-CTR-000305'
  tag gid: 'V-242407'
  tag rid: 'SV-242407r863983_rule'
  tag stig_id: 'CNTR-K8-000890'
  tag fix_id: 'F-45640r863819_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  kubelet_conf_path = input('kubelet_conf_path')

  if kubelet_conf_path
    describe file(kubelet_conf_path) do
      it { should_not be_more_permissive_than('0644') }
    end
  else
    describe kubelet do
      its('config_file') { should_not be_more_permissive_than('0644') }
    end
  end
end
