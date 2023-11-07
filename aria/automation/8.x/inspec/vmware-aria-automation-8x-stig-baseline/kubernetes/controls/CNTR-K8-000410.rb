control 'CNTR-K8-000410' do
  title 'Kubernetes Worker Nodes must not have the sshd service enabled.'
  desc 'Worker Nodes are maintained and monitored by the Control Plane. Direct access and manipulation of the nodes must not take place by administrators. Worker nodes must be treated as immutable and updated via replacement rather than in-place upgrades.'
  desc 'check', "Log in to each worker node. Verify that the sshd service is not enabled. To validate the service is not enabled, run the command:

systemctl is-enabled sshd.service

If the service sshd is enabled, this is a finding.

Note: If console access is not available, SSH access can be attempted. If the worker nodes cannot be reached, this requirement is \"not a finding\"."
  desc 'fix', "To disable the sshd service, run the command:

chkconfig sshd off

Note: If access to the worker node is through an SSH session, it is important to realize there are two requirements for disabling and stopping the sshd service that must be done during the same SSH session. Disabling the service must be performed first and then the service stopped to guarantee both settings can be made if the session is interrupted."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag gid: 'V-242394'
  tag rid: 'SV-242394r863970_rule'
  tag stig_id: 'CNTR-K8-000410'
  tag fix_id: 'F-45627r863784_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe systemd_service('sshd') do
    it { should_not be_enabled }
  end
end
