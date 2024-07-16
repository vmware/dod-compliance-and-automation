control 'ESXI-80-000237' do
  title 'The ESXi host must not be configured to override virtual machine (VM) logger settings.'
  desc 'Each VM on an ESXi host runs in its own "vmx" process. Upon creation, a vmx process will look in two locations for configuration items, the ESXi host itself and the per-vm *.vmx file in the VM storage path on the datastore. The settings on the ESXi host are read first and take precedence over settings in the *.vmx file.

This can be a convenient way to set a setting in one place and have it apply to all VMs running on that host. The difficulty is in managing those settings and determining the effective state. Since managing per-VM vmx settings can be fully automated and customized while the ESXi setting cannot be easily queried, the ESXi configuration must not be used.'
  desc 'check', 'From an ESXi shell, run the following command:

# grep "^vmx\\.log" /etc/vmware/config

If the command produces any output, this is a finding.'
  desc 'fix', 'From an ESXi shell, run the following commands:

# cp /etc/vmware/config /etc/vmware/config.bak
# grep -v "^vmx\\.log" /etc/vmware/config.bak>/etc/vmware/config'
  impact 0.5
  tag check_id: 'C-62532r933435_chk'
  tag severity: 'medium'
  tag gid: 'V-258792'
  tag rid: 'SV-258792r959010_rule'
  tag stig_id: 'ESXI-80-000237'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62441r933436_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
