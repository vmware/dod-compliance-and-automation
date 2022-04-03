control 'PHTN-67-000011' do
  title "The Photon operating system must configure auditd to use the correct
log format."
  desc  "To compile an accurate risk assessment and provide forensic analysis,
it is essential for security personnel to know exact, unfiltered details of the
event in question."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep \"^log_format\" /etc/audit/auditd.conf

    Expected result:

    log_format = RAW

    If there is no output, this is not a finding.

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/audit/auditd.conf with a text editor.

    Ensure that the \"log_format\" line is uncommented and set to the following:

    log_format = RAW

    At the command line, execute the following command:

    # service auditd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000038-GPOS-00016'
  tag gid: 'V-239083'
  tag rid: 'SV-239083r675057_rule'
  tag stig_id: 'PHTN-67-000011'
  tag fix_id: 'F-42253r675056_fix'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3']

  describe auditd_conf do
    its('log_format') { should cmp 'RAW' }
  end
end
