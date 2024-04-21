control 'CNTR-K8-000940' do
  title 'The Kubernetes Controllers must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).'
  desc 'Kubernetes Controller ports, protocols, and services must be controlled and conform to the PPSM CAL. Those PPS that fall outside the PPSM CAL must be blocked. Instructions on the PPSM can be found in DoD Instruction 8551.01 Policy.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep kube-scheduler.manifest -I -secure-port
-edit manifest file:
VIM <Manifest Name:
Review  livenessProbe:
HttpGet:
Port:
Review ports:
- containerPort:
       hostPort:
- containerPort:
       hostPort:
Run Command:
kubectl describe services --all-namespace
Search labels for any controller names spaces.

Any manifest and namespace PPS or services configuration not in compliance with PPSM CAL is a finding.

Review the information systems documentation and interview the team, gain an understanding of the Controller architecture, and determine applicable PPS. Any PPS in the system documentation not in compliance with the CAL PPSM is a finding. Any PPS not set in the system documentation is a finding.

Review findings against the most recent PPSM CAL:
https://cyber.mil/ppsm/cal/

Verify Controller network boundary with the PPS associated with the Controller for Assurance Categories. Any PPS not in compliance with the CAL Assurance Category requirements is a finding.'
  desc 'fix', 'Amend any system documentation requiring revision. Update Kubernetes Controller manifest and namespace PPS configuration to comply with PPSM CAL.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45687r863831_chk'
  tag severity: 'medium'
  tag gid: 'V-242412'
  tag rid: 'SV-242412r879588_rule'
  tag stig_id: 'CNTR-K8-000940'
  tag gtitle: 'SRG-APP-000142-CTR-000330'
  tag fix_id: 'F-45645r712591_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  if kube_controller_manager.exist?
    describe 'This is a manual check. Verify Controllers network boundary with the PPS associated with the CAL Assurance Categories. Any PPS not in compliance with the CAL Assurance Category requirements is a finding.' do
      skip 'This is a manual check. Verify Controllers network boundary with the PPS associated with the CAL Assurance Categories. Any PPS not in compliance with the CAL Assurance Category requirements is a finding.'
    end
  else
    impact 0.0
    describe 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.' do
      skip 'The Kubernetes Controller Manager process is not running on the target so this control is not applicable.'
    end
  end
end
