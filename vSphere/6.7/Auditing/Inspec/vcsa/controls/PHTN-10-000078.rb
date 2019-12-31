control "PHTN-10-000078" do
  title "The Photon operating system must ensure that audit events are flushed
to disk at proper intervals."
  desc  "Without setting a balance between performance and ensuring all audit
events are written to disk, performance of the system may suffer or the risk of
missing audit entries may be too high."
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000078"
  tag stig_id: "PHTN-10-000078"
  tag fix_id: nil
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "CM-6 b"
  tag check: "At the command line, execute the following command:

# grep -E \"freq|flush\" /etc/audit/auditd.conf

Expected result:

flush = INCREMENTAL_ASYNC
freq = 50

If the output does not match the expected result, this is a finding.

"
  tag fix: "Open /etc/audit/auditd.conf with a text editor.

Ensure that the below line is present and any existing 'flush' and 'freq'
settings are removed.

flush = INCREMENTAL_ASYNC
freq = 50"

  describe auditd_conf do
    its("flush") { should cmp 'INCREMENTAL_ASYNC'}
    its("freq") { should cmp '50'}
  end

end

