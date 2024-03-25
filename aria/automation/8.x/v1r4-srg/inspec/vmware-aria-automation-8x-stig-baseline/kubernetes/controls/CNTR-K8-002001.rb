control 'CNTR-K8-002001' do
  title 'Kubernetes must have a Pod Security Admission feature gate set.'
  desc "\"In order to implement Pod Security Admission controller feature gates must be enabled.

Feature gates are a set of key=value pairs that describe Kubernetes features. You can turn these features on or off using the --feature-gates command line flag on each Kubernetes component.\""
  desc 'check', "Check Static Pods:
On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:

grep -i PodSecurity=true *

Ensure the argument \"--feature-gates=PodSecurity=true\" is present in each manifest file.

If kube-apiserver, kube-controller-manager or kube-schedule is missing  the argument \"--feature-gates=PodSecurity=true\", this is a finding.

Check Kubelet:
Run the following command on each Worker Node:
ps -ef | grep kubelet

Verify that the \"--feature-gates=PodSecurity=true\" argument exists. If it doesn't exisit, this is a finding.

Check Control Plane Kubelet config file:
On the Kubernetes Control Plane, run the command:
ps -ef | grep kubelet
Check the config file (path identified by: --config).

Verify that the \"--feature-gates=PodSecurity=true\" argument exists. If it doesn't exisit, this is a finding."
  desc 'fix', "Add the \"--feature-gates=PodSecurity=true\"  argument to every component of Kubernetes.

kube-apiserver, kube-controller-manager and kube-scheduler:
These components are started as static pods, you can find their manifests in the /etc/kubernetes/manifests/ folder.
add \"--feature-gates=PodSecurity=true\" argument in each of the files.

Kubelet:
Edit the Kubernetes Kubelet file in the --config directory on the Kubernetes Control Plane:
Add  \"--feature-gates=PodSecurity=true\"

Reset Kubelet service using the following command:
service kubelet restart

Note: if your cluster has multiple nodes you will need to make the changes on every node where the components are deployed."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag gid: 'V-254801'
  tag rid: 'SV-254801r864044_rule'
  tag stig_id: 'CNTR-K8-002001'
  tag fix_id: 'F-58358r863730_fix'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']

  describe kube_scheduler do
    its('feature-gates.to_s') { should match /PodSecurity=[T|t]rue/ }
  end

  describe kube_controller_manager do
    its('feature-gates.to_s') { should match /PodSecurity=[T|t]rue/ }
  end

  describe kube_apiserver do
    its('feature-gates.to_s') { should match /PodSecurity=[T|t]rue/ }
  end

  kubelet_conf_path = input('kubelet_conf_path')

  if kubelet_conf_path
    describe.one do
      describe kubelet do
        its('feature-gates.to_s') { should match /PodSecurity=[T|t]rue/ }
      end
      describe kubelet_config_file(kubelet_conf_path) do
        its(['featureGates', 'PodSecurity']) { should cmp 'true' }
      end
    end
  else
    describe.one do
      describe kubelet do
        its('feature-gates.to_s') { should match /PodSecurity=[T|t]rue/ }
      end
      describe kubelet_config_file do
        its(['featureGates', 'PodSecurity']) { should cmp 'true' }
      end
    end
  end
end
