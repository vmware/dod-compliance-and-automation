control 'PHTN-50-000186' do
  title 'The Photon operating system must ensure audit events are flushed to disk at proper intervals.'
  desc  'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. To that end, the auditd service must be configured to start automatically and be running at all times.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify auditd is configured to flush audit events to disk regularly:

    # grep -E \"freq|flush\" /etc/audit/auditd.conf

    Example result:

    flush = INCREMENTAL_ASYNC
    freq = 50

    If \"flush\" is not set to \"INCREMENTAL_ASYNC\", this is a finding.
    If \"freq\" is not set to \"50\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/audit/auditd.conf

    Add or update the following lines:

    flush = INCREMENTAL_ASYNC
    freq = 50

    At the command line, run the following command:

    # pkill -SIGHUP auditd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000186'
  tag rid: 'SV-PHTN-50-000186'
  tag stig_id: 'PHTN-50-000186'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe auditd_conf do
    its('flush') { should cmp 'INCREMENTAL_ASYNC' }
    its('freq') { should cmp '50' }
  end
end
