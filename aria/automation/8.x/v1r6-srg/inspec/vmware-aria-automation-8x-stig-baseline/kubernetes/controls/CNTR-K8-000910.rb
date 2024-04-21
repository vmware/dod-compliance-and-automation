control 'CNTR-K8-000910' do
  title 'Kubernetes Controller Manager must disable profiling.'
  desc 'Kubernetes profiling provides the ability to analyze and troubleshoot Controller Manager events over a web interface on a host port. Enabling this service can expose details about the Kubernetes architecture. This service must not be enabled unless deemed necessary.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i profiling *

If the setting "profiling" is not configured in the Kubernetes Controller Manager manifest file or it is set to "True", this is a finding.'
  desc 'fix', 'Edit the Kubernetes Controller Manager manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the argument "--profiling value" to "false".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45684r863824_chk'
  tag severity: 'medium'
  tag gid: 'V-242409'
  tag rid: 'SV-242409r879587_rule'
  tag stig_id: 'CNTR-K8-000910'
  tag gtitle: 'SRG-APP-000141-CTR-000315'
  tag fix_id: 'F-45642r863825_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  if kube_controller_manager.exist?
    describe kube_controller_manager do
      its('profiling') { should cmp 'false' }
    end
  else
    impact 0.0
    describe 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.'
    end
  end
end
