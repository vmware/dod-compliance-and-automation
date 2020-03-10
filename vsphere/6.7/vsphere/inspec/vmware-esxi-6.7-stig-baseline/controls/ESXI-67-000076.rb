control "ESXI-67-000076" do
  title "The ESXi host must enable Secure Boot."
  desc  "Secure Boot is a protocol of UEFI firmware that ensures the integrity
of the boot process from hardware up through to the OS. Secure Boot for ESXi
requires support from the firmware and it requires that all ESXi kernel
modules, drivers and VIBs be signed by VMware or a partner subordinate."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000076"
  tag stig_id: "ESXI-67-000076"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "Temporarily enable SSH, connect to the ESXi host and run the
following command:

/usr/lib/vmware/secureboot/bin/secureBoot.py -s

If the output is not Enabled, this is a finding."
  desc 'fix', "Temporarily enable SSH, connect to the ESXi host and run the
following command:

/usr/lib/vmware/secureboot/bin/secureBoot.py -c

If the output indicates that Secure Boot cannot be enabled, correct \xC2\xA0the
discrepencies and try again. If the discrepencies cannot be rectified this
finding is downgraded to a CAT III.

Consult your vendor documentation and boot the host into BIOS setup mode.
Enable UEFI boot mode and Secure Boot. Restart the host.

Temporarily enable SSH, connect to the ESXi host and run the following command
to verify that Secure Boot is enabled:

/usr/lib/vmware/secureboot/bin/secureBoot.py -s"

  describe "" do
    skip 'Manual verification is required for this control'
  end

end

