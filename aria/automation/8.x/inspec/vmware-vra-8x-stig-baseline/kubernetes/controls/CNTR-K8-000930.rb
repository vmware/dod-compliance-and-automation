control 'CNTR-K8-000930' do
  title 'The Kubernetes Scheduler must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).'
  desc 'Kubernetes Scheduler PPS must be controlled and conform to the PPSM CAL. Those ports, protocols, and services that fall outside the PPSM CAL must be blocked. Instructions on the PPSM can be found in DoD Instruction 8551.01 Policy.'
  desc 'check', "Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep kube-scheduler.manifest -I -insecure-port
                grep kube-scheduler.manifest -I -secure-port
-edit manifest file:
VIM &lt;Manifest Name&gt;
Review  livenessProbe:
HttpGet:
Port:
Review ports:
- containerPort:
       hostPort:
- containerPort:
       hostPort:
Run Command:
kubectl describe services –all-namespace
Search labels for any scheduler names spaces.
Port:

Any manifest and namespace PPS configuration not in compliance with PPSM CAL is a finding.

Review the information systems documentation and interview the team, gain an understanding of the Scheduler architecture, and determine applicable PPS. Any PPS in the system documentation not in compliance with the CAL PPSM is a finding. Any PPSs not set in the system documentation is a finding.

Review findings against the most recent PPSM CAL:
https://cyber.mil/ppsm/cal/

Verify Scheduler network boundary with the PPS associated with the CAL Assurance Categories. Any PPS not in compliance with the CAL Assurance Category requirements is a finding."
  desc 'fix', 'Amend any system documentation requiring revision. Update Kubernetes Scheduler manifest and namespace PPS configuration to comply with the PPSM CAL.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-CTR-000325'
  tag gid: 'V-242411'
  tag rid: 'SV-242411r863987_rule'
  tag stig_id: 'CNTR-K8-000930'
  tag fix_id: 'F-45644r712588_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']

  describe 'Verify Scheduler server network boundary with the PPS associated with the CAL Assurance Categories. Any PPS not in compliance with the CAL Assurance Category requirements is a finding.' do
    skip 'This is a manual check.'
  end
end
