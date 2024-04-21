control 'CNTR-K8-001460' do
  title 'Kubernetes Kubelet must enable tlsPrivateKeyFile for client authentication to secure service.'
  desc 'Kubernetes container and pod configuration are maintained by Kubelet. Kubelet agents register nodes with the API Server, mount volume storage, and perform health checks for containers and pods. Anyone who gains access to Kubelet agents can effectively control applications within the pods and containers. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols such as TLS. TLS provides the Kubernetes API Server with a means to authenticate sessions and encrypt traffic.

To enable encrypted communication for Kubelet, the tlsPrivateKeyFile must be set. This parameter gives the location of the SSL Certificate Authority file used to secure Kubelet communication.'
  desc 'check', 'On the Control Plane, run the command:
ps -ef | grep kubelet

If the "--tls-private-key-file" option exists, this is a finding.

Note the path to the config file (identified by --config).

Run the command:
grep -i tlsPrivateKeyFile <path_to_config_file>

If the setting "tlsPrivateKeyFile" is not set or contains no value, this is a finding.'
  desc 'fix', 'On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "--tls-private-key-file" option if present.

Note the path to the config file (identified by --config).

Edit the Kubernetes Kubelet config file:
Set "tlsPrivateKeyFile" to  a path containing the appropriate private key.

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45699r918180_chk'
  tag severity: 'medium'
  tag gid: 'V-242424'
  tag rid: 'SV-242424r918182_rule'
  tag stig_id: 'CNTR-K8-001460'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45657r918181_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  if kube_apiserver.exist?
    kubelet_process = input('kubelet_process')
    kubelet_conf_path = input('kubelet_conf_path')

    # If rotateCertificates and serverTLSBootstrap are true then kubelet will automatically request a certificate for use from kubeapi and rotate it when expiration approaches as well which meets the intent of this rule
    describe kubelet(kubelet_process) do
      its('tls-private-key-file') { should be nil }
    end
    if kubelet_conf_path
      describe.one do
        describe kubelet_config_file(kubelet_conf_path) do
          its('tlsPrivateKeyFile') { should_not be_nil }
        end
        describe kubelet_config_file(kubelet_conf_path) do
          its('rotateCertificates') { should cmp 'true' }
          its('serverTLSBootstrap') { should cmp 'true' }
        end
      end
    else
      describe.one do
        describe kubelet_config_file do
          its('tlsPrivateKeyFile') { should_not be_nil }
        end
        describe kubelet_config_file do
          its('rotateCertificates') { should cmp 'true' }
          its('serverTLSBootstrap') { should cmp 'true' }
        end
      end
    end
  else
    impact 0.0
    describe 'This control does not apply to worker nodes so this is not applicable.' do
      skip 'This control does not apply to worker nodes so this is not applicable.'
    end
  end
end
