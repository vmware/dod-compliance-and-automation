control 'CNTR-K8-000320' do
  title 'The Kubernetes API server must have the insecure port flag disabled.'
  desc "By default, the API server will listen on two ports. One port is the secure port and the other port is called the \"localhost port\". This port is also called the \"insecure port\", port 8080. Any requests to this port bypass authentication and authorization checks. If this port is left open, anyone who gains access to the host on which the Control Plane is running can bypass all authorization and authentication mechanisms put in place, and have full control over the entire cluster.

Close the insecure port by setting the API server's --insecure-port flag to \"0\", ensuring that the --insecure-bind-address is not set."
  desc 'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

grep -i insecure-port *

If the setting insecure-port is not set to \"0\" or is not configured in the Kubernetes API server manifest file, this is a finding.

NOTE: --insecure-port flag has been deprecated and can only be set to 0, **This flag  will be removed in v1.24.*"
  desc 'fix', "Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the argument --insecure-port to \"0\"."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag gid: 'V-242386'
  tag rid: 'SV-242386r863962_rule'
  tag stig_id: 'CNTR-K8-000320'
  tag fix_id: 'F-45619r863762_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('insecure-port') { should cmp '0' }
  end
end
