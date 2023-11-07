control 'CNTR-K8-000190' do
  title 'The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination.'
  desc "The Kubernetes API Server will prohibit the use of SSL and unauthorized versions of TLS protocols to properly secure communication.

The use of unsupported protocol exposes vulnerabilities to the Kubernetes by rogue traffic interceptions, man-in-the-middle attacks, and impersonation of users or services from the container platform runtime, registry, and keystore. To enable the minimum version of TLS to be used by the Kubernetes API Server, the setting \"peer-auto-tls\" must be set."
  desc 'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

grep -I  peer-auto-tls *

If the setting \"peer-auto-tls\" is not configured in the Kubernetes etcd manifest file or it is set to \"true\", this is a finding."
  desc 'fix', 'Edit the Kubernetes etcd manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "peer-auto-tls" to "false".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-CTR-000035'
  tag gid: 'V-242380'
  tag rid: 'SV-242380r863956_rule'
  tag stig_id: 'CNTR-K8-000190'
  tag fix_id: 'F-45613r863744_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  unless etcd.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe.one do
    describe etcd do
      # Default is false if not specified and should be considered compliant per https://etcd.io/docs/v3.5/op-guide/configuration/
      its('peer-auto-tls') { should be_nil.or eq('false') }
    end
    describe process_env_var('etcd') do
      its(:ETCD_PEER_AUTO_TLS) { should cmp 'false' }
    end
  end
end
