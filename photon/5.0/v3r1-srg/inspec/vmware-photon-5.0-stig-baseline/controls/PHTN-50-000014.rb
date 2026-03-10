control 'PHTN-50-000014' do
  title 'The Photon operating system must configure auditd to log to disk.'
  desc  "
    Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

    Audit record content must be shipped to a central location, but it must also be logged locally.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify auditd is configured to write logs to disk:

    # grep '^write_logs' /etc/audit/auditd.conf

    Example result:

    write_logs = yes

    If there is no output, this is not a finding.

    If \"write_logs\" exists and is not configured to \"yes\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/auditd.conf

    Ensure the \"write_logs\" line is uncommented and set to the following:

    write_logs = yes

    At the command line, run the following command:

    # pkill -SIGHUP auditd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag gid: 'V-PHTN-50-000014'
  tag rid: 'SV-PHTN-50-000014'
  tag stig_id: 'PHTN-50-000014'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']

  describe.one do
    describe auditd_conf do
      its('write_logs') { should eq nil }
    end
    describe auditd_conf do
      its('write_logs') { should cmp 'yes' }
    end
  end
end
