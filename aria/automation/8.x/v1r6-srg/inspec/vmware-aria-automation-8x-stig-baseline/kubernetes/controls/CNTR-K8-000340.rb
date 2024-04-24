control 'CNTR-K8-000340' do
  title 'The Kubernetes API server must have the insecure bind address not set.'
  desc %q(By default, the API server will listen on two ports and addresses. One address is the secure address and the other address is called the "insecure bind" address and is set by default to localhost. Any requests to this address bypass authentication and authorization checks. If this insecure bind address is set to localhost, anyone who gains access to the host on which the Control Plane is running can bypass all authorization and authentication mechanisms put in place and have full control over the entire cluster.

Close or set the insecure bind address by setting the API server's "--insecure-bind-address" flag to an IP or leave it unset and ensure that the "--insecure-bind-port" is not set.)
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

grep -i insecure-bind-address *

If the setting "--insecure-bind-address" is found and set to "localhost" in the Kubernetes API manifest file, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Remove the value of "--insecure-bind-address" setting.'
  impact 0.7
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45663r927082_chk'
  tag severity: 'high'
  tag gid: 'V-242388'
  tag rid: 'SV-242388r927242_rule'
  tag stig_id: 'CNTR-K8-000340'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45621r927083_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  if kube_apiserver.exist?
    describe kube_apiserver do
      its('insecure-bind-address') { should be_nil }
    end
  else
    impact 0.0
    describe 'The Kubernetes API server process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes API server process is not running on the target so this control is not applicable.'
    end
  end
end
