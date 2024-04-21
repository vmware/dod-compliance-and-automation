control 'CNTR-K8-000900' do
  title 'The Kubernetes manifest files must have least privileges.'
  desc 'The manifest files contain the runtime configuration of the API server, scheduler, controller, and etcd. If an attacker can gain access to these files, changes can be made to open vulnerabilities and bypass user authorizations inherent within Kubernetes with RBAC implemented.

'
  desc 'check', 'On both Control Plane and Worker Nodes, change to the /etc/kubernetes/manifest directory. Run the command:
ls -l *

Each manifest file must have permissions "644" or more restrictive.

If any manifest file is less restrictive than "644", this is a finding.'
  desc 'fix', 'On both Control Plane and Worker Nodes, change to the /etc/kubernetes/manifest directory. Run the command:
chmod 644 *

To verify the change took place, run the command:
ls -l *

All the manifest files should now have privileges of "644".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45683r918172_chk'
  tag severity: 'medium'
  tag gid: 'V-242408'
  tag rid: 'SV-242408r918174_rule'
  tag stig_id: 'CNTR-K8-000900'
  tag gtitle: 'SRG-APP-000133-CTR-000310'
  tag fix_id: 'F-45641r918173_fix'
  tag satisfies: ['SRG-APP-000133-CTR-000310', 'SRG-APP-000133-CTR-000295', 'SRG-APP-000516-CTR-001335']
  tag 'documentable'
  tag cci: ['CCI-001499', 'CCI-000366']
  tag nist: ['CM-5 (6)', 'CM-6 b']

  manifests_path = input('manifests_path')

  manifests_files = command("find #{manifests_path} -type f").stdout.split
  if !manifests_files.empty?
    manifests_files.each do |file_name|
      describe file(file_name) do
        it { should_not be_more_permissive_than('0644') }
      end
    end
  else
    describe "Kubernetes manifest files not present of the target at specified path #{manifests_path}." do
      skip "Kubernetes manifest files not present of the target at specified path #{manifests_path}."
    end
  end
end
