control 'CNTR-K8-000460' do
  title 'Kubernetes DynamicKubeletConfig must not be enabled.'
  desc 'Kubernetes allows a user to configure kubelets with dynamic configurations. When dynamic configuration is used, the kubelet will watch for changes to the configuration file. When changes are made, the kubelet will automatically restart. Allowing this capability bypasses access restrictions and authorizations. Using this capability, an attacker can lower the security posture of the kubelet, which includes allowing the ability to run arbitrary commands in any container running on that node.'
  desc 'check', %q(This check is only applicable for Kubernetes versions 1.25 and older.

On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

In each manifest file, if the feature-gates does not exist, or does not contain the "DynamicKubeletConfig" flag, or sets the flag to "true", this is a finding.

On each Control Plane and Worker node, run the command:
ps -ef | grep kubelet

Verify the "feature-gates" option is not present.

Note the path to the config file (identified by --config).

Inspect the content of the config file:
If the "featureGates" setting is not present, or does not contain the "DynamicKubeletConfig", or sets the flag to "true", this is a finding.)
  desc 'fix', %q(This fix is only applicable to Kubernetes version 1.25 and older.

On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Edit the manifest files so that every manifest has a "--feature-gates" setting with "DynamicKubeletConfig=false".

On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "feature-gates" option if present.

Note the path to the config file (identified by --config).

Edit the config file:
Add a "featureGates" setting if one does not yet exist. Add the feature gate "DynamicKubeletConfig=false".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet)
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45674r918162_chk'
  tag severity: 'medium'
  tag gid: 'V-242399'
  tag rid: 'SV-242399r918164_rule'
  tag stig_id: 'CNTR-K8-000460'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45632r918163_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  # This control is no longer part of Kubernetes 1.24+  See https://kubernetes.io/docs/tasks/administer-cluster/reconfigure-kubelet/
  server_version = Semverse::Version.new(bash("kubelet --version | awk -F' ' '{ print $2 }' |sed s/^v//").stdout.chomp)
  server_version_major = server_version.major
  server_version_minor = server_version.minor
  if server_version_major.to_i >= 1 && server_version_minor.to_i >= 24
    impact 0.0
    describe "DynamicKubeletConfig removed in v1.24 and greater and is not applicable to version #{server_version}" do
      skip "DynamicKubeletConfig removed in v1.24 and greater and is not applicable to version #{server_version}"
    end
  else
    kubelet_process = input('kubelet_process')
    kubelet_conf_path = input('kubelet_conf_path')

    if kube_apiserver.exist?
      describe kube_apiserver do
        its('feature-gates.to_s') { should match /DynamicKubeletConfig=[F|f]alse/ }
      end
    end

    if kube_scheduler.exist?
      describe kube_scheduler do
        its('feature-gates.to_s') { should match /DynamicKubeletConfig=[F|f]alse/ }
      end
    end

    if kube_controller_manager.exist?
      describe kube_controller_manager do
        its('feature-gates.to_s') { should match /DynamicKubeletConfig=[F|f]alse/ }
      end
    end

    # Check kubelet part of this control
    if kubelet_conf_path
      describe.one do
        describe kubelet(kubelet_process) do
          its('feature-gates.to_s') { should match /DynamicKubeletConfig=[F|f]alse/ }
        end
        describe kubelet_config_file(kubelet_conf_path) do
          its(['featureGates', 'DynamicKubeletConfig']) { should cmp 'false' }
        end
      end
    else
      describe.one do
        describe kubelet(kubelet_process) do
          its('feature-gates.to_s') { should match /DynamicKubeletConfig=[F|f]alse/ }
        end
        describe kubelet_config_file do
          its(['featureGates', 'DynamicKubeletConfig']) { should cmp 'false' }
        end
      end
    end
  end
end
