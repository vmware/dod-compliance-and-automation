control 'CNTR-K8-000460' do
  title 'Kubernetes DynamicKubeletConfig must not be enabled.'
  desc 'Kubernetes allows a user to configure kubelets with dynamic configurations. When dynamic configuration is used, the kubelet will watch for changes to the configuration file. When changes are made, the kubelet will automatically restart. Allowing this capability bypasses access restrictions and authorizations. Using this capability, an attacker can lower the security posture of the kubelet, which includes allowing the ability to run arbitrary commands in any container running on that node.'
  desc 'check', "On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Review the feature-gates setting if one is returned.

If the feature-gates setting does not exist or feature-gates does not contain the DynamicKubeletConfig flag or the \"DynamicKubletConfig\" flag is set to \"true\", this is a finding.

Change to the directory /etc/sysconfig on the Control Plane and each Worker node and execute the command:
grep -i feature-gates kubelet

Review every feature-gates setting if one is returned.

If the feature-gates setting does not exist or feature-gates does not contain the DynamicKubeletConfig flag or the DynamicKubletConfig flag is set to \"true\", this is a finding."
  desc 'fix', "Edit any manifest file or kubelet config file that does not contain a feature-gates setting or has DynamicKubeletConfig set to \"true\".

An omission of DynamicKubeletConfig within the feature-gates defaults to true. Set DynamicKubeletConfig to \"false\". Restart the kubelet service if the kubelet config file is changed."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag gid: 'V-242399'
  tag rid: 'SV-242399r863975_rule'
  tag stig_id: 'CNTR-K8-000460'
  tag fix_id: 'F-45632r863797_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe kube_scheduler do
    its('feature-gates.to_s') { should match /DynamicKubeletConfig=[F|f]alse/ }
  end

  describe kube_controller_manager do
    its('feature-gates.to_s') { should match /DynamicKubeletConfig=[F|f]alse/ }
  end

  describe kube_apiserver do
    its('feature-gates.to_s') { should match /DynamicKubeletConfig=[F|f]alse/ }
  end

  kubelet_conf_path = input('kubelet_conf_path')

  if kubelet_conf_path
    describe.one do
      describe kubelet do
        its('feature-gates.to_s') { should match /DynamicKubeletConfig=[F|f]alse/ }
      end
      describe kubelet_config_file(kubelet_conf_path) do
        its(['featureGates', 'DynamicKubeletConfig']) { should_not cmp 'false' }
      end
    end
  else
    describe.one do
      describe kubelet do
        its('feature-gates.to_s') { should match /DynamicKubeletConfig=[F|f]alse/ }
      end
      describe kubelet_config_file do
        its(['featureGates', 'DynamicKubeletConfig']) { should_not cmp 'false' }
      end
    end
  end
end
