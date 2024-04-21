control 'CNTR-K8-000350' do
  title 'The Kubernetes API server must have the secure port set.'
  desc %q(By default, the API server will listen on what is rightfully called the secure port, port 6443. Any requests to this port will perform authentication and authorization checks. If this port is disabled, anyone who gains access to the host on which the Control Plane is running has full control of the entire cluster over encrypted traffic.

Open the secure port by setting the API server's "--secure-port" flag to a value other than "0".)
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

grep -i secure-port *

If the setting "--secure-port" is set to "0" or is not configured in the Kubernetes API manifest file, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--secure-port" to a value greater than "0".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45664r927085_chk'
  tag severity: 'medium'
  tag gid: 'V-242389'
  tag rid: 'SV-242389r927243_rule'
  tag stig_id: 'CNTR-K8-000350'
  tag gtitle: 'SRG-APP-000033-CTR-000100'
  tag fix_id: 'F-45622r927086_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  if kube_apiserver.exist?
    describe kube_apiserver do
      its('secure-port') { should cmp > 0 }
    end
  else
    impact 0.0
    describe 'The Kubernetes API server process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes API server process is not running on the target so this control is not applicable.'
    end
  end
end
