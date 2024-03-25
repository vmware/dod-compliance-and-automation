control 'CNTR-K8-003310' do
  title 'The Kubernetes API Server audit log retention must be set.'
  desc 'The Kubernetes API Server must set enough storage to retain logs for monitoring suspicious activity and system misconfiguration, and provide evidence for Cyber Security Investigations.'
  desc 'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i audit-log-maxage *

If the setting \"audit-log-maxage\" is not set in the Kubernetes API Server manifest file or it is set less than \"30\", this is a finding."
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--audit-log-maxage" to a minimum of "30".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'V-242464'
  tag rid: 'SV-242464r864029_rule'
  tag stig_id: 'CNTR-K8-003310'
  tag fix_id: 'F-45697r863932_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('audit-log-maxage') { should cmp >= 30 }
  end
end
