control 'CNTR-K8-003270' do
  title 'The Kubernetes admin kubeconfig must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes admin kubeconfig files contain the arguments and settings for the Control Plane services. These services are controller and scheduler. If these files can be changed, the scheduler will be implementing the changes immediately.'
  desc 'check', 'Review the permissions of the Kubernetes config files by using the command:

stat -c %a /etc/kubernetes/admin.conf
stat -c %a /etc/kubernetes/scheduler.conf
stat -c %a /etc/kubernetes/controller-manager.conf

If any of the files are have permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of the conf files to "644" by executing the command:

chmod 644 /etc/kubernetes/admin.conf
chmod 644 /etc/kubernetes/scheduler.conf
chmod 644 /etc/kubernetes/controller-manager.conf'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45735r712734_chk'
  tag severity: 'medium'
  tag gid: 'V-242460'
  tag rid: 'SV-242460r927262_rule'
  tag stig_id: 'CNTR-K8-003270'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45693r712735_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if kube_apiserver.exist?
    input('kubernetes_conf_files').each do |file_name|
      if file(file_name).exist?
        describe file(file_name) do
          it { should_not be_more_permissive_than('0644') }
        end
      else
        describe "Kubernetes Conf file #{file_name} not found on target." do
          skip "Kubernetes Conf file #{file_name} not found on target."
        end
      end
    end
  else
    impact 0.0
    describe 'This control does not apply to worker nodes so this is not applicable.' do
      skip 'This control does not apply to worker nodes so this is not applicable.'
    end
  end
end
