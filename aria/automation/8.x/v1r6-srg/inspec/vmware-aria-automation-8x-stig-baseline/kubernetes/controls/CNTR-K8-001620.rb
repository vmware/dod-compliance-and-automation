control 'CNTR-K8-001620' do
  title 'Kubernetes Kubelet must enable kernel protection.'
  desc 'System kernel is responsible for memory, disk, and task management. The kernel provides a gateway between the system hardware and software. Kubernetes requires kernel access to allocate resources to the Control Plane. Threat actors that penetrate the system kernel can inject malicious code or hijack the Kubernetes architecture. It is vital to implement protections through Kubernetes components to reduce the attack surface.'
  desc 'check', 'On the Control Plane, run the command:
ps -ef | grep kubelet

If the "--protect-kernel-defaults" option exists, this is a finding.

Note the path to the config file (identified by --config).

Run the command:
grep -i protectKernelDefaults <path_to_config_file>

If the setting "protectKernelDefaults" is not set or is set to false, this is a finding.'
  desc 'fix', 'On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "--protect-kernel-defaults" option if present.

Note the path to the Kubernetes Kubelet config file (identified by --config).

Edit the Kubernetes Kubelet config file:
Set "protectKernelDefaults" to "true".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45709r918186_chk'
  tag severity: 'high'
  tag gid: 'V-242434'
  tag rid: 'SV-242434r918188_rule'
  tag stig_id: 'CNTR-K8-001620'
  tag gtitle: 'SRG-APP-000233-CTR-000585'
  tag fix_id: 'F-45667r918187_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  if kube_apiserver.exist?
    kubelet_process = input('kubelet_process')
    kubelet_conf_path = input('kubelet_conf_path')

    describe kubelet(kubelet_process) do
      its('protect-kernel-defaults') { should be nil }
    end
    if kubelet_conf_path
      describe kubelet_config_file(kubelet_conf_path) do
        its('protectKernelDefaults') { should cmp 'true' }
      end
    else
      describe kubelet_config_file do
        its('protectKernelDefaults') { should cmp 'true' }
      end
    end
  else
    impact 0.0
    describe 'This control does not apply to worker nodes so this is not applicable.' do
      skip 'This control does not apply to worker nodes so this is not applicable.'
    end
  end
end
