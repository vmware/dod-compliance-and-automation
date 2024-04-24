control 'CNTR-K8-001430' do
  title 'Kubernetes Controller Manager must have the SSL Certificate Authority set.'
  desc 'The Kubernetes Controller Manager is responsible for creating service accounts and tokens for the API Server, maintaining the correct number of pods for every replication controller and provides notifications when nodes are offline.

Anyone who gains access to the Controller Manager can generate backdoor accounts, take possession of, or diminish system performance without detection by disabling system notification. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols, such as TLS. TLS provides the Kubernetes Controller Manager with a means to be able to authenticate sessions and encrypt traffic.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i root-ca-file *

If the setting "--root-ca-file" is not set in the Kubernetes Controller Manager manifest file or contains no value, this is a finding.'
  desc 'fix', 'Edit the Kubernetes Controller Manager manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--root-ca-file" to path containing Approved Organizational Certificate.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45696r927107_chk'
  tag severity: 'medium'
  tag gid: 'V-242421'
  tag rid: 'SV-242421r927251_rule'
  tag stig_id: 'CNTR-K8-001430'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45654r927108_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  if kube_controller_manager.exist?
    describe kube_controller_manager do
      its('root-ca-file') { should_not be_nil }
    end
  else
    impact 0.0
    describe 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.'
    end
  end
end
