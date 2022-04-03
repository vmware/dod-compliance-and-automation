control 'PHTN-67-000010' do
  title 'The Photon operating system must configure auditd to log to disk.'
  desc  "Without establishing what type of events occurred, it would be
difficult to establish, correlate, and investigate the events leading up to an
outage or attack.

    Audit record content must be shipped to a central location, but it must
also be logged locally.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep \"^write_logs\" /etc/audit/auditd.conf

    Expected result:

    write_logs = yes

    If there is no output, this is not a finding.

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/audit/auditd.conf with a text editor.

    Ensure that the \"write_logs\" line is uncommented and set to the following:

    write_logs = yes

    At the command line, execute the following command:

    # service auditd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000039-GPOS-00017',
'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019']
  tag gid: 'V-239082'
  tag rid: 'SV-239082r675054_rule'
  tag stig_id: 'PHTN-67-000010'
  tag fix_id: 'F-42252r675053_fix'
  tag cci: ['CCI-000130', 'CCI-000132', 'CCI-000133', 'CCI-000134']
  tag nist: ['AU-3', 'AU-3', 'AU-3', 'AU-3']

  describe.one do
    describe auditd_conf do
      its('write_logs') { should eq nil }
    end

    describe auditd_conf do
      its('write_logs') { should cmp 'yes' }
    end
  end
end
