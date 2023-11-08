control 'CNTR-K8-000470' do
  title 'The Kubernetes API server must have Alpha APIs disabled.'
  desc 'Kubernetes allows alpha API calls within the API server. The alpha features are disabled by default since they are not ready for production and likely to change without notice. These features may also contain security issues that are rectified as the feature matures. To keep the Kubernetes cluster secure and stable, these alpha features must not be used.'
  desc 'check', "On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Review the feature-gates setting, if one is returned.

If the feature-gates setting is available and contains the AllAlpha flag set to \"true\", this is a finding."
  desc 'fix', "Edit any manifest files that contain the feature-gates setting with AllAlpha set to \"true\". Set the flag to \"false\" or remove the AllAlpha setting completely.
(AllAlpha- default=false)"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag gid: 'V-242400'
  tag rid: 'SV-242400r863976_rule'
  tag stig_id: 'CNTR-K8-000470'
  tag fix_id: 'F-45633r712555_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe kube_scheduler do
    its('feature-gates.to_s') { should_not match /AllAlpha=[T|t]rue/ }
  end

  describe kube_controller_manager do
    its('feature-gates.to_s') { should_not match /AllAlpha=[T|t]rue/ }
  end

  describe kube_apiserver do
    its('feature-gates.to_s') { should_not match /AllAlpha=[T|t]rue/ }
  end

  kubelet_conf_path = input('kubelet_conf_path')

  if kubelet_conf_path
    describe.one do
      describe kubelet do
        its('feature-gates.to_s') { should_not match /AllAlpha=[T|t]rue/ }
      end
      describe kubelet_config_file(kubelet_conf_path) do
        its(['featureGates', 'AllAlpha']) { should_not cmp 'true' }
      end
    end
  else
    describe.one do
      describe kubelet do
        its('feature-gates.to_s') { should_not match /AllAlpha=[T|t]rue/ }
      end
      describe kubelet_config_file do
        its(['featureGates', 'AllAlpha']) { should_not cmp 'true' }
      end
    end
  end
end
