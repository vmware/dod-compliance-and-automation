control 'VMCH-67-000020' do
  title "System administrators must use templates to deploy virtual machines
whenever possible."
  desc  "By capturing a hardened base operating system image (with no
applications installed) in a template, ensure all virtual machines are created
with a known baseline level of security. Then use this template to create
other, application-specific templates, or use the application template to
deploy virtual machines. Manual installation of the OS and applications into a
VM introduces the risk of misconfiguration due to human or process error."
  desc  'rationale', ''
  desc  'check', "
    Ask the SA if hardened, patched templates are used for VM creation,
properly configured OS deployments, including applications both dependent and
non-dependent on VM-specific configurations.

    If hardened, patched templates are not used for VM creation, this is a
finding.
  "
  desc 'fix', "Create hardened virtual machine templates to use for OS
deployments."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239351'
  tag rid: 'SV-239351r679602_rule'
  tag stig_id: 'VMCH-67-000020'
  tag fix_id: 'F-42543r679601_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
