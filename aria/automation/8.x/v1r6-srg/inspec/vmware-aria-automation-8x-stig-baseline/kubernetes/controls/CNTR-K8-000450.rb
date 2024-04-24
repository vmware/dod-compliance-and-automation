control 'CNTR-K8-000450' do
  title 'Kubernetes DynamicAuditing must not be enabled.'
  desc 'Protecting the audit data from change or deletion is important when an attack occurs. One way an attacker can cover their tracks is to change or delete audit records. This will either make the attack unnoticeable or make it more difficult to investigate how the attack took place and what changes were made. The audit data can be protected through audit log file protections and user authorization.

One way for an attacker to thwart these measures is to send the audit logs to another source and filter the audited results before sending them on to the original target. This can be done in Kubernetes through the configuration of dynamic audit webhooks through the DynamicAuditing flag.'
  desc 'check', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Review the feature-gates setting, if one is returned.

If the feature-gates setting is available and contains the DynamicAuditing flag set to "true", this is a finding.

On each Control Plane and Worker node, run the command:
ps -ef | grep kubelet

If the "--feature-gates" option exists, this is a finding.

Note the path to the config file (identified by: --config).

Inspect the content of the config file:
If the "featureGates" setting is present and has the "DynamicAuditing" flag set to "true", this is a finding.)
  desc 'fix', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

If any "--feature-gates" setting is available and contains the "DynamicAuditing" flag, remove the flag or set it to false.

On the each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "--feature-gates option" if present.

Note the path to the config file (identified by: --config).

Edit the Kubernetes Kubelet config file:
If the "featureGates" setting is present, remove the "DynamicAuditing" flag or set the flag to false.

Restart the kubelet service using the following command:
service kubelet restart)
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45673r918159_chk'
  tag severity: 'medium'
  tag gid: 'V-242398'
  tag rid: 'SV-242398r918161_rule'
  tag stig_id: 'CNTR-K8-000450'
  tag gtitle: 'SRG-APP-000033-CTR-000100'
  tag fix_id: 'F-45631r918160_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  kubelet_process = input('kubelet_process')
  kubelet_conf_path = input('kubelet_conf_path')

  if kube_apiserver.exist?
    describe kube_apiserver do
      its('feature-gates.to_s') { should_not match /DynamicAuditing=[T|t]rue/ }
    end
  end

  if kube_scheduler.exist?
    describe kube_scheduler do
      its('feature-gates.to_s') { should_not match /DynamicAuditing=[T|t]rue/ }
    end
  end

  if kube_controller_manager.exist?
    describe kube_controller_manager do
      its('feature-gates.to_s') { should_not match /DynamicAuditing=[T|t]rue/ }
    end
  end

  # Check kubelet part of this control
  describe kubelet(kubelet_process) do
    its('feature-gates') { should be nil }
  end
  if kubelet_conf_path
    describe kubelet_config_file(kubelet_conf_path) do
      its(['featureGates', 'DynamicAuditing']) { should_not cmp 'true' }
    end
  else
    describe kubelet_config_file do
      its(['featureGates', 'DynamicAuditing']) { should_not cmp 'true' }
    end
  end
end
