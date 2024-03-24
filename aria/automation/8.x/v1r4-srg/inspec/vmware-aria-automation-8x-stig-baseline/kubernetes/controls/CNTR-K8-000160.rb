control 'CNTR-K8-000160' do
  title 'The Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.'
  desc "The Kubernetes Scheduler will prohibit the use of SSL and unauthorized versions of TLS protocols to properly secure communication.

The use of unsupported protocol exposes vulnerabilities to the Kubernetes by rogue traffic interceptions, man-in-the-middle attacks, and impersonation of users or services from the container platform runtime, registry, and keystore. To enable the minimum version of TLS to be used by the Kubernetes API Server, the setting \"tls-min-version\" must be set."
  desc 'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:

grep -i tls-min-version *

If the setting \"tls-min-version\" is not configured in the Kubernetes Scheduler manifest file or it is set to \"VersionTLS10\" or \"VersionTLS11\", this is a finding."
  desc 'fix', 'Edit the Kubernetes Scheduler manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--tls-min-version" to "VersionTLS12" or higher.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-CTR-000035'
  tag gid: 'V-242377'
  tag rid: 'SV-242377r863953_rule'
  tag stig_id: 'CNTR-K8-000160'
  tag fix_id: 'F-45610r863735_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  unless kube_scheduler.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes Scheduler process is not running on the target.'
  end

  describe.one do
    describe kube_scheduler do
      its('tls-min-version') { should cmp 'VersionTLS12' }
    end
    describe kube_scheduler do
      its('tls-min-version') { should cmp 'VersionTLS13' }
    end
  end
end
