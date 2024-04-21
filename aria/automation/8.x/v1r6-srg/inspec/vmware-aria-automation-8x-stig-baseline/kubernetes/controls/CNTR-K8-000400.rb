control 'CNTR-K8-000400' do
  title 'Kubernetes Worker Nodes must not have sshd service running.'
  desc 'Worker Nodes are maintained and monitored by the Control Plane. Direct access and manipulation of the nodes should not take place by administrators. Worker nodes should be treated as immutable and updated via replacement rather than in-place upgrades.'
  desc 'check', 'Log in to each worker node. Verify that the sshd service is not running. To validate that the service is not running, run the command:

systemctl status sshd

If the service sshd is active (running), this is a finding.

Note: If console access is not available, SSH access can be attempted. If the worker nodes cannot be reached, this requirement is "not a finding".'
  desc 'fix', 'To stop the sshd service, run the command:

systemctl stop sshd

Note: If access to the worker node is through an SSH session, it is important to realize there are two requirements for disabling and stopping the sshd service and they should be done during the same SSH session. Disabling the service must be performed first and then the service stopped to guarantee both settings can be made if the session is interrupted.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45668r712533_chk'
  tag severity: 'medium'
  tag gid: 'V-242393'
  tag rid: 'SV-242393r879530_rule'
  tag stig_id: 'CNTR-K8-000400'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45626r863782_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  if kube_apiserver.exist?
    impact 0.0
    describe 'This control does not apply to control plane nodes so this is not applicable.' do
      skip 'This control does not apply to control plane nodes so this is not applicable.'
    end
  else
    describe systemd_service('sshd') do
      it { should_not be_running }
    end
  end
end
