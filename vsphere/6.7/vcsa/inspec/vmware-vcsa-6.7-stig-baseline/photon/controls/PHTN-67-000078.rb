control 'PHTN-67-000078' do
  title "The Photon operating system must ensure audit events are flushed to
disk at proper intervals."
  desc  "Without setting a balance between performance and ensuring all audit
events are written to disk, performance of the system may suffer or the risk of
missing audit entries may be too high."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep -E \"freq|flush\" /etc/audit/auditd.conf

    Expected result:

    flush = INCREMENTAL_ASYNC
    freq = 50

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/audit/auditd.conf with a text editor.

    Ensure that the line below is present and any existing \"flush\" and
\"freq\" settings are removed.

    flush = INCREMENTAL_ASYNC
    freq = 50
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239149'
  tag rid: 'SV-239149r675255_rule'
  tag stig_id: 'PHTN-67-000078'
  tag fix_id: 'F-42319r675254_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe auditd_conf do
    its('flush') { should cmp 'INCREMENTAL_ASYNC' }
    its('freq') { should cmp '50' }
  end
end
