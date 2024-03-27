control 'CNTR-K8-001420' do
  title 'Kubernetes Kubelet must have the SSL Certificate Authority set.'
  desc "Kubernetes container and pod configuration are maintained by Kubelet. Kubelet agents register nodes with the API Server, mount volume storage, and perform health checks for containers and pods. Anyone who gains access to Kubelet agents can effectively control applications within the pods and containers. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols, such as TLS. TLS provides the Kubernetes API Server with a means to be able to authenticate sessions and encrypt traffic.

To enable encrypted communication for Kubelet, the client-ca-file must be set. This parameter gives the location of the SSL Certificate Authority file used to secure Kubelet communication."
  desc 'check', "On the Kubernetes Control Plane, run the command:
ps -ef | grep kubelet
Check the config file (path identified by: --config):

Change to the directory identified by --config (example /etc/sysconfig/) run the command:
grep -i client-ca-file kubelet

If the setting client-ca-file is not set in the Kubernetes API server manifest file or contains no value, this is a finding."
  desc 'fix', "Edit the Kubernetes Kubelet file in the --config directory on the Kubernetes Control Plane:
Set the value of client-ca-file to path containing Approved Organizational Certificate.

Reset Kubelet service using the following command:
service kubelet restart"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag gid: 'V-242420'
  tag rid: 'SV-242420r863995_rule'
  tag stig_id: 'CNTR-K8-001420'
  tag fix_id: 'F-45653r863849_fix'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  kubelet_conf_path = input('kubelet_conf_path')

  if kubelet_conf_path
    describe.one do
      describe kubelet do
        its('client-ca-file') { should_not be_nil }
      end
      describe kubelet_config_file(kubelet_conf_path) do
        its(['authentication', 'x509', 'clientCAFile']) { should_not be_nil }
      end
    end
  else
    describe.one do
      describe kubelet do
        its('client-ca-file') { should_not be_nil }
      end
      describe kubelet_config_file do
        its(['authentication', 'x509', 'clientCAFile']) { should_not be_nil }
      end
    end
  end
end
