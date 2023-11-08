control 'CNTR-K8-003320' do
  title 'The Kubernetes API Server audit log path must be set.'
  desc 'Kubernetes API Server validates and configures pods and services for the API object. The REST operation provides frontend functionality to the cluster share state. Audit logs are necessary to provide evidence in the case the Kubernetes API Server is compromised requiring Cyber Security Investigation. To record events in the audit log the log path value must be set.'
  desc 'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i audit-log-path *

If the setting audit-log-path is not set in the Kubernetes API Server manifest file or it is not set to a valid path, this is a finding."
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--audit-log-path" to valid location.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag gid: 'V-242465'
  tag rid: 'SV-242465r864030_rule'
  tag stig_id: 'CNTR-K8-003320'
  tag fix_id: 'F-45698r863935_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  unless kube_apiserver.exist?
    impact 0.0
    desc 'caveat', 'Kubernetes API Server process is not running on the target.'
  end

  describe kube_apiserver do
    its('audit-log-path') { should_not be_nil }
  end

  if kube_apiserver.params['audit-log-path']
    describe file(kube_apiserver.params['audit-log-path'].join) do
      it { should exist }
    end
  end
end
