control 'CNTR-K8-000470' do
  title 'The Kubernetes API server must have Alpha APIs disabled.'
  desc 'Kubernetes allows alpha API calls within the API server. The alpha features are disabled by default since they are not ready for production and likely to change without notice. These features may also contain security issues that are rectified as the feature matures. To keep the Kubernetes cluster secure and stable, these alpha features must not be used.'
  desc 'check', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Review the "--feature-gates" setting, if one is returned.

If the "--feature-gate"s setting is available and contains the "AllAlpha" flag set to "true", this is a finding.)
  desc 'fix', 'Edit any manifest file that contains the "--feature-gates" setting with "AllAlpha" set to "true".

Set the value of "AllAlpha" to "false" or remove the setting completely. (AllAlpha - default=false)'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45675r927094_chk'
  tag severity: 'medium'
  tag gid: 'V-242400'
  tag rid: 'SV-242400r927246_rule'
  tag stig_id: 'CNTR-K8-000470'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag fix_id: 'F-45633r927095_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  kubelet_process = input('kubelet_process')
  kubelet_conf_path = input('kubelet_conf_path')

  if kube_apiserver.exist?
    describe kube_apiserver do
      its('feature-gates.to_s') { should_not match /AllAlpha=[T|t]rue/ }
    end
  end

  if kube_scheduler.exist?
    describe kube_scheduler do
      its('feature-gates.to_s') { should_not match /AllAlpha=[T|t]rue/ }
    end
  end

  if kube_controller_manager.exist?
    describe kube_controller_manager do
      its('feature-gates.to_s') { should_not match /AllAlpha=[T|t]rue/ }
    end
  end

  # Check kubelet part of this control
  if kubelet_conf_path
    describe.one do
      describe kubelet(kubelet_process) do
        its('feature-gates.to_s') { should_not match /AllAlpha=[T|t]rue/ }
      end
      describe kubelet_config_file(kubelet_conf_path) do
        its(['featureGates', 'AllAlpha']) { should_not cmp 'true' }
      end
    end
  else
    describe.one do
      describe kubelet(kubelet_process) do
        its('feature-gates.to_s') { should_not match /AllAlpha=[T|t]rue/ }
      end
      describe kubelet_config_file do
        its(['featureGates', 'AllAlpha']) { should_not cmp 'true' }
      end
    end
  end
end
