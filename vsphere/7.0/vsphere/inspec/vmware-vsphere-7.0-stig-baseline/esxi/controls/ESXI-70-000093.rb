control 'ESXI-70-000093' do
  title 'The ESXi host must not be configured to override virtual machine logger settings.'
  desc  "
    Each virtual machine on an ESXi host runs in its own \"vmx\" process. Upon creation, a vmx process will look in two locations for configuration items, the ESXi host itself and the per-vm *.vmx file in the VM storage path on the datastore. The settings on the ESXi host are read first and take precedence over settings in the *.vmx file.

    This can be a convenient way to set a setting in one place and have it apply to all VMs running on that host. The difficulty is in managing those settings and determining the effective state. Since managing per-VM vmx settings can be fully automated and customized while the ESXi setting cannot be easily queried, the ESXi configuration must not be used.
  "
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # grep \"^vmx\\.log\" /etc/vmware/config

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, run the following command(s):

    # \\cp /etc/vmware/config /etc/vmware/config.bak
    # grep -v \"^vmx\\.log\" /etc/vmware/config.bak>/etc/vmware/config
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000093'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
