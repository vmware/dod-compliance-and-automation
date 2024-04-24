control 'CNTR-K8-000310' do
  title 'The Kubernetes Controller Manager must have secure binding.'
  desc 'Limiting the number of attack vectors and implementing authentication and encryption on the endpoints available to external sources is paramount when securing the overall Kubernetes cluster. The Controller Manager API service exposes port 10252/TCP by default for health and metrics information use. This port does not encrypt or authenticate connections. If this port is exposed externally, an attacker can use this port to attack the entire Kubernetes cluster. By setting the bind address to only localhost (i.e., 127.0.0.1), only those internal services that require health and metrics information can access the Control Manager API.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

grep -i bind-address *

If the setting bind-address is not set to "127.0.0.1" or is not found in the Kubernetes Controller Manager manifest file, this is a finding.'
  desc 'fix', 'Edit the Kubernetes Controller Manager manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the argument "--bind-address" to "127.0.0.1".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45660r863758_chk'
  tag severity: 'medium'
  tag gid: 'V-242385'
  tag rid: 'SV-242385r879530_rule'
  tag stig_id: 'CNTR-K8-000310'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag fix_id: 'F-45618r863759_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  if kube_controller_manager.exist?
    describe kube_controller_manager do
      its('bind-address') { should cmp '127.0.0.1' }
    end
  else
    impact 0.0
    describe 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.'
    end
  end
end
