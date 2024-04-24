control 'CNTR-K8-000880' do
  title 'The Kubernetes KubeletConfiguration file must be owned by root.'
  desc 'The kubelet configuration file contains the runtime configuration of the kubelet service. If an attacker can gain access to this file, changes can be made to open vulnerabilities and bypass user authorizations inherent within Kubernetes with RBAC implemented.'
  desc 'check', 'On the Kubernetes Control Plane and Worker nodes, run the command:
ps -ef | grep kubelet

Check the config file (path identified by: --config):

Change to the directory identified by --config (example /etc/sysconfig/) run the command:
ls -l kubelet

Each kubelet configuration file must be owned by root:root.

If any manifest file is not owned by root:root, this is a finding.'
  desc 'fix', 'On the Control Plane and Worker nodes, change to the --config directory. Run the command:
chown root:root kubelet

To verify the change took place, run the command:
ls -l kubelet

The kubelet file should now be owned by root:root.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45681r863815_chk'
  tag severity: 'medium'
  tag gid: 'V-242406'
  tag rid: 'SV-242406r918168_rule'
  tag stig_id: 'CNTR-K8-000880'
  tag gtitle: 'SRG-APP-000133-CTR-000300'
  tag fix_id: 'F-45639r863816_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  kubelet_process = input('kubelet_process')
  kubelet_conf_path = input('kubelet_conf_path')

  if kubelet_conf_path
    describe file(kubelet_conf_path) do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
    end
  else
    describe kubelet(kubelet_process) do
      its('config_file') { should be_owned_by('root') }
      its('config_file') { should be_grouped_into('root') }
    end
  end
end
