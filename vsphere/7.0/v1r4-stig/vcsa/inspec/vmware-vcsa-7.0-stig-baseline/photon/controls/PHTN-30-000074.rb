control 'PHTN-30-000074' do
  title 'The Photon operating system must ensure audit events are flushed to disk at proper intervals.'
  desc 'Without setting a balance between performance and ensuring all audit events are written to disk, performance of the system may suffer or the risk of missing audit entries may be too high.'
  desc 'check', 'At the command line, run the following command:

# grep -E "freq|flush" /etc/audit/auditd.conf

Expected result:

flush = INCREMENTAL_ASYNC
freq = 50

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/audit/auditd.conf

Ensure the following line is present and any existing "flush" and "freq" settings are removed:

flush = INCREMENTAL_ASYNC
freq = 50'
  impact 0.5
  tag check_id: 'C-60219r887304_chk'
  tag severity: 'medium'
  tag gid: 'V-256544'
  tag rid: 'SV-256544r887306_rule'
  tag stig_id: 'PHTN-30-000074'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60162r887305_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe auditd_conf do
    its('flush') { should cmp 'INCREMENTAL_ASYNC' }
    its('freq') { should cmp '50' }
  end
end
