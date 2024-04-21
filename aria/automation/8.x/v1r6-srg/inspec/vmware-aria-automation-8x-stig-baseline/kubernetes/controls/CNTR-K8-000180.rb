control 'CNTR-K8-000180' do
  title 'The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination.'
  desc 'Kubernetes etcd will prohibit the use of SSL and unauthorized versions of TLS protocols to properly secure communication.

The use of unsupported protocol exposes vulnerabilities to the Kubernetes by rogue traffic interceptions, man-in-the-middle attacks, and impersonation of users or services from the container platform runtime, registry, and keystore. To enable the minimum version of TLS to be used by the Kubernetes API Server, the setting "--auto-tls" must be set.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

grep -i  auto-tls *

If the setting "--auto-tls" is not configured in the Kubernetes etcd manifest file or it is set to true, this is a finding.'
  desc 'fix', 'Edit the Kubernetes etcd manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane.

Set the value of "--auto-tls" to "false".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45654r927069_chk'
  tag severity: 'medium'
  tag gid: 'V-242379'
  tag rid: 'SV-242379r927237_rule'
  tag stig_id: 'CNTR-K8-000180'
  tag gtitle: 'SRG-APP-000014-CTR-000035'
  tag fix_id: 'F-45612r927070_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  if etcd.exist?
    describe.one do
      describe etcd do
        its('auto-tls') { should cmp 'false' }
      end
      # Environment variables: every flag has a corresponding environment variable that has the same name but is prefixed with ETCD_ and formatted in all caps and snake case. For example, --some-flag would be ETCD_SOME_FLAG.
      describe process_env_var('etcd') do
        its(:ETCD_AUTO_TLS) { should cmp 'false' }
      end
    end
  else
    impact 0.0
    describe 'The Kubernetes etcd process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes etcd process is not running on the target so this control is not applicable.'
    end
  end
end
