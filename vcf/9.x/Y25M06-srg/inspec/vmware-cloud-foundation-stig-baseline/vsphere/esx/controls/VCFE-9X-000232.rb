control 'VCFE-9X-000232' do
  title 'The ESX host must not be configured to override virtual machine (VM) configurations.'
  desc  "
    Each VM on an ESX host runs in its own \"vmx\" process. Upon creation, a vmx process will look in two locations for configuration items, the ESX host itself and the per-vm *.vmx file in the VM storage path on the datastore. The settings on the ESX host are read first and take precedence over settings in the *.vmx file.

    This can be a convenient way to set a setting in one place and have it apply to all VMs running on that host. The difficulty is in managing those settings and determining the effective state. Since managing per-VM vmx settings can be fully automated and customized while the ESX setting cannot be easily queried, the ESX configuration must not be used.
  "
  desc  'rationale', ''
  desc  'check', "
    From an ESX shell, run the following command:

    # stat -c \"%s\" /etc/vmware/settings

    Expected result:

    0

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESX shell, run the following command:

    # echo -n >/etc/vmware/settings
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000232'
  tag rid: 'SV-VCFE-9X-000232'
  tag stig_id: 'VCFE-9X-000232'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
    skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
  end
end
