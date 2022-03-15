control 'ESXI-67-000076' do
  title 'The ESXi host must enable Secure Boot.'
  desc  "Secure Boot is a protocol of UEFI firmware that ensures the integrity
of the boot process from hardware up through to the OS. Secure Boot for ESXi
requires support from the firmware and requires that all ESXi kernel modules,
drivers, and vSphere Installation Bundles (VIBs) be signed by VMware or a
partner subordinate."
  desc  'rationale', ''
  desc  'check', "
    Temporarily enable SSH, connect to the ESXi host, and run the following
command:

    /usr/lib/vmware/secureboot/bin/secureBoot.py -s

    If the output is not \"Enabled\", this is a finding.
  "
  desc 'fix', "
    Temporarily enable SSH, connect to the ESXi host, and run the following
command:

    /usr/lib/vmware/secureboot/bin/secureBoot.py -c

    If the output indicates that Secure Boot cannot be enabled, correct the
discrepancies and try again. If the discrepancies cannot be rectified, this
finding is downgraded to a CAT III.

    Consult vendor documentation and boot the host into BIOS setup mode. Enable
UEFI boot mode and Secure Boot. Restart the host.

    Temporarily enable SSH, connect to the ESXi host, and run the following
command to verify that Secure Boot is enabled:

    /usr/lib/vmware/secureboot/bin/secureBoot.py -s
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239327'
  tag rid: 'SV-239327r674910_rule'
  tag stig_id: 'ESXI-67-000076'
  tag fix_id: 'F-42519r674909_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
