control 'CNTR-K8-003310' do
  title 'The Kubernetes API Server audit log retention must be set.'
  desc 'The Kubernetes API Server must set enough storage to retain logs for monitoring suspicious activity and system misconfiguration, and provide evidence for Cyber Security Investigations.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i audit-log-maxage *

If the setting "audit-log-maxage" is not set in the Kubernetes API Server manifest file or it is set less than "30", this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--audit-log-maxage" to a minimum of "30".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45739r863931_chk'
  tag severity: 'medium'
  tag gid: 'V-242464'
  tag rid: 'SV-242464r879887_rule'
  tag stig_id: 'CNTR-K8-003310'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45697r863932_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if kube_apiserver.exist?
    describe kube_apiserver do
      its('audit-log-maxage') { should cmp >= 30 }
    end
  else
    impact 0.0
    describe 'The Kubernetes API server process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes API server process is not running on the target so this control is not applicable.'
    end
  end
end
