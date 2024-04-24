control 'CNTR-K8-001410' do
  title 'Kubernetes API Server must have the SSL Certificate Authority set.'
  desc 'Kubernetes control plane and external communication are managed by API Server. The main implementation of the API Server is to manage hardware resources for pods and containers using horizontal or vertical scaling. Anyone who can access the API Server can effectively control the Kubernetes architecture. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols such as TLS. TLS provides the Kubernetes API Server with a means to authenticate sessions and encrypt traffic.

To enable encrypted communication for API Server, the parameter client-ca-file must be set. This parameter gives the location of the SSL Certificate Authority file used to secure API Server communication.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i client-ca-file *

If the setting feature client-ca-file is not set in the Kubernetes API server manifest file or contains no value, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--client-ca-file" to path containing Approved Organizational Certificate.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45694r863845_chk'
  tag severity: 'medium'
  tag gid: 'V-242419'
  tag rid: 'SV-242419r918176_rule'
  tag stig_id: 'CNTR-K8-001410'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45652r918175_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']

  if kube_apiserver.exist?
    describe kube_apiserver do
      its('client-ca-file') { should_not be_nil }
    end
  else
    impact 0.0
    describe 'The Kubernetes API server process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes API server process is not running on the target so this control is not applicable.'
    end
  end
end
