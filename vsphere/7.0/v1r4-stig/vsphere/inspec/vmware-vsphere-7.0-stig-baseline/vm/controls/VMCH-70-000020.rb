control 'VMCH-70-000020' do
  title 'System administrators must use templates to deploy virtual machines (VMs) whenever possible.'
  desc 'Capture a hardened base operating system image (with no applications installed) in a template to ensure all VMs are created with a known baseline level of security. Use this template to create other, application-specific templates, or use the application template to deploy VMs. Manual installation of the operating system and applications into a VM introduces the risk of misconfiguration due to human or process error.'
  desc 'check', 'Ask the system administrator if hardened, patched templates are used for VM creation and properly configured operating system deployments, including applications dependent and nondependent on VM-specific configurations.

If hardened, patched templates are not used for VM creation, this is a finding.'
  desc 'fix', 'Create hardened VM templates to use for operating system deployments.'
  impact 0.3
  tag check_id: 'C-60143r886445_chk'
  tag severity: 'low'
  tag gid: 'V-256468'
  tag rid: 'SV-256468r886447_rule'
  tag stig_id: 'VMCH-70-000020'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60086r886446_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
