control 'CNTR-K8-003350' do
  title 'The Kubernetes API Server must prohibit communication using TLS version 1.0 and 1.1, and SSL 2.0 and 3.0.'
  desc "The Kubernetes API Server will prohibit the use of SSL and unauthorized versions of TLS protocols to properly secure communication.

The use of unsupported protocol exposes vulnerabilities to Kubernetes by rogue traffic interceptions, man-in-the middle attacks, and impersonation of users or services from the container platform runtime, registry, and keystore. To enable the minimum version of TLS to be used by the Kubernetes API Server, the setting \"tls-min-version\" must be set.

The container platform and its components will adhere to NIST 800-52R2."
  desc 'check', "Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
grep -i tls-min-version *

If the setting tls-min-version is not configured in the Kubernetes API Server manifest file or it is set to \"VersionTLS10\" or \"VersionTLS11\", this is a finding."
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--tls-min-version" to either "VersionTLS12" or higher.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000560-CTR-001340'
  tag gid: 'V-242468'
  tag rid: 'SV-242468r864031_rule'
  tag stig_id: 'CNTR-K8-003350'
  tag fix_id: 'F-45701r863938_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe.one do
    describe kube_apiserver do
      its('tls-min-version') { should cmp 'VersionTLS12' }
    end
    describe kube_apiserver do
      its('tls-min-version') { should cmp 'VersionTLS13' }
    end
  end
end
