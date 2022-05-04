control 'ESXI-70-000076' do
  title 'The ESXi host must enable Secure Boot.'
  desc  "
    Secure Boot is part of the UEFI firmware standard. With UEFI Secure Boot enabled, a host refuses to load any UEFI driver or app unless the operating system bootloader has a valid digital signature. Secure Boot for ESXi requires support from the firmware and it requires that all ESXi kernel modules, drivers and vSphere Installation Bundles (VIBs) be signed by VMware or a partner subordinate.

    Secure Boot is enabled in the BIOS of the ESXi physical server and supported by the hypervisor boot loader. There is no ESXi control to 'turn on' Secure Boot. Requiring Secure Boot (failing to boot without it present) is accomplished in another control.
  "
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # /usr/lib/vmware/secureboot/bin/secureBoot.py -s

    If the output is not \"Enabled\", this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, run the following command(s):

    # /usr/lib/vmware/secureboot/bin/secureBoot.py -c

    If the output indicates that Secure Boot cannot be enabled, correct the discrepencies and try again.

    If the discrepencies cannot be rectified, this finding is downgraded to a CAT III.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000076'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
