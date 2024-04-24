control 'CNTR-K8-002001' do
  title 'Kubernetes must enable PodSecurity admission controller on static pods and Kubelets.'
  desc 'PodSecurity admission controller is a component that validates and enforces security policies for pods running within a Kubernetes cluster. It is responsible for evaluating the security context and configuration of pods against defined policies.

To enable PodSecurity admission controller on Static Pods (kube-apiserver, kube-controller-manager, or kube-schedule), the argument "--feature-gates=PodSecurity=true" must be set.

To enable PodSecurity admission controller on Kubelets, the featureGates PodSecurity=true argument must be set.

(Note: The PodSecurity feature gate is GA as of  v1.25.)'
  desc 'check', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

For each manifest file, if the "--feature-gates" setting does not exist, does not contain the "--PodSecurity" flag, or sets the flag to "false", this is a finding.

On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

If the "--feature-gates" option exists, this is a finding.

Note the path to the config file (identified by --config).

Inspect the content of the config file:
If the "featureGates" setting is not present, does not contain the "PodSecurity" flag, or sets the flag to "false", this is a finding.)
  desc 'fix', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Ensure the argument "--feature-gates=PodSecurity=true" is present in each manifest file.

On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "--feature-gates" option if present.

Note the path to the config file (identified by --config).

Edit the Kubernetes Kubelet config file:
Add a "featureGates" setting if one does not yet exist. Add the feature gate "PodSecurity=true".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet)
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-58412r918278_chk'
  tag severity: 'high'
  tag gid: 'V-254801'
  tag rid: 'SV-254801r918279_rule'
  tag stig_id: 'CNTR-K8-002001'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag fix_id: 'F-58358r918213_fix'
  tag 'documentable'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']

  kubelet_process = input('kubelet_process')
  kubelet_conf_path = input('kubelet_conf_path')

  # This feature did not exist prior to 1.22. In 1.22 the default was false. In 1.23-1.27 the default was true. In 1.28+ this feature gate no longer exists. See https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
  server_version = Semverse::Version.new(bash("kubelet --version | awk -F' ' '{ print $2 }' |sed s/^v//").stdout.chomp)
  server_version_major = server_version.major
  server_version_minor = server_version.minor
  if server_version_major.to_i >= 1 && server_version_minor.to_i < 22
    impact 0.0
    describe "PodSecurity did not exist in versions prior to 1.22 and is not applicable to version #{server_version}" do
      skip "PodSecurity did not exist in versions prior to 1.22 and is not applicable to version #{server_version}"
    end
  elsif server_version_major.to_i >= 1 && server_version_minor.to_i == 22
    if kube_apiserver.exist?
      describe kube_apiserver do
        its('feature-gates.to_s') { should match /PodSecurity=[T|t]rue/ }
      end
    end

    if kube_scheduler.exist?
      describe kube_scheduler do
        its('feature-gates.to_s') { should match /PodSecurity=[T|t]rue/ }
      end
    end

    if kube_controller_manager.exist?
      describe kube_controller_manager do
        its('feature-gates.to_s') { should match /PodSecurity=[T|t]rue/ }
      end
    end
    # Check kubelet part of this control
    describe kubelet(kubelet_process) do
      its('feature-gates.to_s') { should be nil }
    end
    if kubelet_conf_path
      describe kubelet_config_file(kubelet_conf_path) do
        its(['featureGates', 'PodSecurity']) { should cmp 'true' }
      end
    else
      describe kubelet_config_file do
        its(['featureGates', 'PodSecurity']) { should cmp 'true' }
      end
    end
  elsif server_version_major.to_i >= 1 && server_version_minor.to_i >= 23 && server_version_minor.to_i <= 28
    if kube_apiserver.exist?
      describe.one do
        describe kube_apiserver do
          its('feature-gates.to_s') { should match /PodSecurity=[T|t]rue/ }
        end
        describe kube_apiserver do
          its('feature-gates.to_s') { should_not match /PodSecurity/ }
        end
      end
    end

    if kube_scheduler.exist?
      describe.one do
        describe kube_scheduler do
          its('feature-gates.to_s') { should match /PodSecurity=[T|t]rue/ }
        end
        describe kube_scheduler do
          its('feature-gates.to_s') { should_not match /PodSecurity/ }
        end
      end
    end

    if kube_controller_manager.exist?
      describe.one do
        describe kube_controller_manager do
          its('feature-gates.to_s') { should match /PodSecurity=[T|t]rue/ }
        end
        describe kube_controller_manager do
          its('feature-gates.to_s') { should_not match /PodSecurity/ }
        end
      end
    end
    # Check kubelet part of this control
    describe kubelet(kubelet_process) do
      its('feature-gates') { should be nil }
    end
    if kubelet_conf_path
      describe.one do
        describe kubelet_config_file(kubelet_conf_path) do
          its(['featureGates', 'PodSecurity']) { should cmp 'true' }
        end
        describe kubelet_config_file(kubelet_conf_path) do
          its(['featureGates', 'PodSecurity']) { should be nil }
        end
      end
    else
      describe.one do
        describe kubelet_config_file do
          its(['featureGates', 'PodSecurity']) { should cmp 'true' }
        end
        describe kubelet_config_file do
          its(['featureGates', 'PodSecurity']) { should be nil }
        end
      end
    end
  elsif server_version_major.to_i >= 1 && server_version_minor.to_i >= 28
    impact 0.0
    describe "PodSecurity is no longer a feature gate in 1.28+ and is not applicable to version #{server_version}" do
      skip "PodSecurity is no longer a feature gate in 1.28+ and is not applicable to version #{server_version}"
    end
  else
    describe 'Did not detect Kubernetes version...skipping...' do
      skip 'Did not detect Kubernetes version...skipping...'
    end
  end
end
