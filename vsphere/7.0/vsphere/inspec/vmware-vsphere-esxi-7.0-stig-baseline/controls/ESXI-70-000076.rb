# encoding: UTF-8

control 'ESXI-70-000076' do
  title 'The ESXi host must enable Secure Boot.'
  desc  "Secure Boot is a protocol of UEFI firmware that ensures the integrity
of the boot process from hardware up through to the OS. Secure Boot for ESXi
requires support from the firmware and it requires that all ESXi kernel
modules, drivers and VIBs be signed by VMware or a partner subordinate."
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # /usr/lib/vmware/secureboot/bin/secureBoot.py -s

    If the output is not Enabled, this is a finding.
  "
  desc  'fix', "
    From an ESXi shell, run the following command(s):

    # /usr/lib/vmware/secureboot/bin/secureBoot.py -c

    If the output indicates that Secure Boot cannot be enabled, correct  the
discrepencies and try again. If the discrepencies cannot be rectified, this
finding is downgraded to a CAT III.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000076'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  describe "This check is a manual or policy based check" do
    skip "This must be reviewed manually"
  end

end

