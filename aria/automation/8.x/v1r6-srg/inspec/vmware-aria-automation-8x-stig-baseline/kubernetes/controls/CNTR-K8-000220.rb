control 'CNTR-K8-000220' do
  title 'The Kubernetes Controller Manager must create unique service accounts for each work payload.'
  desc 'The Kubernetes Controller Manager is a background process that embeds core control loops regulating cluster system state through the API Server. Every process executed in a pod has an associated service account. By default, service accounts use the same credentials for authentication. Implementing the default settings poses a High risk to the Kubernetes Controller Manager. Setting the "--use-service-account-credential" value lowers the attack surface by generating unique service accounts settings for each controller instance.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

grep -i use-service-account-credentials *

If the setting "--use-service-account-credentials" is not configured in the Kubernetes Controller Manager manifest file or it is set to "false", this is a finding.'
  desc 'fix', 'Edit the Kubernetes Controller Manager manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--use-service-account-credentials" to "true".'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45656r927075_chk'
  tag severity: 'high'
  tag gid: 'V-242381'
  tag rid: 'SV-242381r927239_rule'
  tag stig_id: 'CNTR-K8-000220'
  tag gtitle: 'SRG-APP-000023-CTR-000055'
  tag fix_id: 'F-45614r927076_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']

  if kube_controller_manager.exist?
    describe kube_controller_manager do
      its('use-service-account-credentials') { should cmp 'true' }
    end
  else
    impact 0.0
    describe 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.'
    end
  end
end
