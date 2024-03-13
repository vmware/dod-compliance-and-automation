control 'PHTN-30-000011' do
  title 'The Photon operating system must configure auditd to use the correct log format.'
  desc 'To compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know exact, unfiltered details of the event in question.'
  desc 'check', 'At the command line, run the following command:

# grep "^log_format" /etc/audit/auditd.conf

Expected result:

log_format = RAW

If there is no output, this is not a finding.

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/audit/auditd.conf

Ensure the "log_format" line is uncommented and set to the following:

log_format = RAW

At the command line, run the following command:

# killproc auditd -TERM
# systemctl start auditd'
  impact 0.5
  tag check_id: 'C-60163r887136_chk'
  tag severity: 'medium'
  tag gid: 'V-256488'
  tag rid: 'SV-256488r887138_rule'
  tag stig_id: 'PHTN-30-000011'
  tag gtitle: 'SRG-OS-000038-GPOS-00016'
  tag fix_id: 'F-60106r887137_fix'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']

  describe auditd_conf do
    its('log_format') { should cmp 'RAW' }
  end
end
