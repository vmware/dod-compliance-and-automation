control 'CNTR-K8-001480' do
  title 'Kubernetes etcd must enable client authentication to secure service.'
  desc 'Kubernetes container and pod configuration are maintained by Kubelet. Kubelet agents register nodes with the API Server, mount volume storage, and perform health checks for containers and pods. Anyone who gains access to Kubelet agents can effectively control applications within the pods and containers. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols, such as TLS. TLS provides the Kubernetes API Server with a means to be able to authenticate sessions and encrypt traffic.

Etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive and should be accessible only by authenticated etcd peers in the etcd cluster. The parameter "--peer-client-cert-auth" must be set for etcd to check all incoming peer requests from the cluster for valid client certificates.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
grep -i peer-client-cert-auth *

If the setting "--peer-client-cert-auth" is not configured in the Kubernetes etcd manifest file or set to "false", this is a finding.'
  desc 'fix', 'Edit the Kubernetes etcd manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--peer-client-cert-auth" to "true" for the etcd.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45701r927110_chk'
  tag severity: 'medium'
  tag gid: 'V-242426'
  tag rid: 'SV-242426r927252_rule'
  tag stig_id: 'CNTR-K8-001480'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45659r927111_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  if etcd.exist?
    describe.one do
      describe etcd do
        its('peer-client-cert-auth') { should cmp 'true' }
      end
      # Environment variables: every flag has a corresponding environment variable that has the same name but is prefixed with ETCD_ and formatted in all caps and snake case. For example, --some-flag would be ETCD_SOME_FLAG.
      describe process_env_var('etcd') do
        its(:ETCD_PEER_CLIENT_CERT_AUTH) { should cmp 'true' }
      end
    end
  else
    impact 0.0
    describe 'The Kubernetes etcd process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes etcd process is not running on the target so this control is not applicable.'
    end
  end
end
