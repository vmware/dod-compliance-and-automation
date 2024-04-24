control 'CNTR-K8-003300' do
  title 'The Kubernetes API Server must be set to audit log maximum backup.'
  desc 'The Kubernetes API Server must set enough storage to retain logs for monitoring suspicious activity and system misconfiguration, and provide evidence for Cyber Security Investigations.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i audit-log-maxbackup *

If the setting "audit-log-maxbackup" is not set in the Kubernetes API Server manifest file or it is set less than "10", this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--audit-log-maxbackup" to a minimum of "10".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45738r863928_chk'
  tag severity: 'medium'
  tag gid: 'V-242463'
  tag rid: 'SV-242463r879887_rule'
  tag stig_id: 'CNTR-K8-003300'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45696r863929_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if kube_apiserver.exist?
    describe kube_apiserver do
      its('audit-log-maxbackup') { should cmp >= 10 }
    end
  else
    impact 0.0
    describe 'The Kubernetes API server process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes API server process is not running on the target so this control is not applicable.'
    end
  end
end
