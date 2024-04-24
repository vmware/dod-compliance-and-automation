control 'CNTR-K8-000150' do
  title 'The Kubernetes Controller Manager must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.'
  desc 'The Kubernetes Controller Manager will prohibit the use of SSL and unauthorized versions of TLS protocols to properly secure communication.

The use of unsupported protocol exposes vulnerabilities to the Kubernetes by rogue traffic interceptions, man-in-the-middle attacks, and impersonation of users or services from the container platform runtime, registry, and key store. To enable the minimum version of TLS to be used by the Kubernetes Controller Manager, the setting "tls-min-version" must be set.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:

grep -i tls-min-version *

If the setting "tls-min-version" is not configured in the Kubernetes Controller Manager manifest file or it is set to "VersionTLS10" or "VersionTLS11", this is a finding.'
  desc 'fix', 'Edit the Kubernetes Controller Manager manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--tls-min-version" to "VersionTLS12" or higher.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45651r863731_chk'
  tag severity: 'medium'
  tag gid: 'V-242376'
  tag rid: 'SV-242376r879519_rule'
  tag stig_id: 'CNTR-K8-000150'
  tag gtitle: 'SRG-APP-000014-CTR-000035'
  tag fix_id: 'F-45609r863732_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  if kube_controller_manager.exist?
    describe.one do
      describe kube_controller_manager do
        its('tls-min-version') { should cmp 'VersionTLS12' }
      end
      describe kube_controller_manager do
        its('tls-min-version') { should cmp 'VersionTLS13' }
      end
    end
  else
    impact 0.0
    describe 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.'
    end
  end
end
