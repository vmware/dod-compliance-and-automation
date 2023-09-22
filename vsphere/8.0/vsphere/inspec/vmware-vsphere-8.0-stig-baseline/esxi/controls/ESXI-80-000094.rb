control 'ESXI-80-000094' do
  title 'The ESXi host must enable Secure Boot.'
  desc  "
    Secure Boot is part of the Unified Extensible Firmware Interface (UEFI) firmware standard. With UEFI Secure Boot enabled, a host refuses to load any UEFI driver or app unless the operating system bootloader has a valid digital signature. Secure Boot for ESXi requires support from the firmware and requires that all ESXi kernel modules, drivers, and vSphere Installation Bundles (VIBs) be signed by VMware or a partner subordinate.

    Secure Boot is enabled in the BIOS of the ESXi physical server and supported by the hypervisor boot loader. There is no ESXi control to \"turn on\" Secure Boot. Requiring Secure Boot (failing to boot without it present) is accomplished in another control.
  "
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # /usr/lib/vmware/secureboot/bin/secureBoot.py -s

    If Secure Boot is not \"Enabled\", this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, run the following command:

    # /usr/lib/vmware/secureboot/bin/secureBoot.py -c

    If the output indicates that Secure Boot cannot be enabled, correct the discrepancies and try again.

    Once all discrepancies are resolved, the server ESXi is installed on can be updated to enable Secure Boot in the firmware.

    To enable Secure Boot in the server's firmware follow the instructions for the specific manufacturer.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000278-VMM-001000'
  tag gid: 'V-ESXI-80-000094'
  tag rid: 'SV-ESXI-80-000094'
  tag stig_id: 'ESXI-80-000094'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
