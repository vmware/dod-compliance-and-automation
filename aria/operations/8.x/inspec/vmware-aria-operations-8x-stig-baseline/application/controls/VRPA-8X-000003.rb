control 'VRPA-8X-000003' do
  title 'vRealize Operations Manager must back up log records at least every seven days onto a different system or system component than the system or component being logged.'
  desc  'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to a different system or onto separate media from the system the application server is actually running on helps to assure that in the event of a catastrophic system failure, the log records will be retained.'
  desc  'rationale', ''
  desc  'check', "
    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Log Forwarding.

    If \"Output logs to external log server\" is not checked, this is a finding.

    If all the available logs are not selected for forwarding, this is a finding.

    If log forwarding (Log Insight or syslog) is not configured with an appropriate site-specific server, this is a finding.
  "
  desc 'fix', "
    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Log Forwarding.

    Check the box next to \"Output logs to external log server\". Select all logs.

    Configure a site-specific Log Insight or syslog server. Click \"Apply Changes\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000125-AS-000084'
  tag satisfies: %w(SRG-APP-000181-AS-000255 SRG-APP-000356-AS-000202 SRG-APP-000358-AS-000064 SRG-APP-000515-AS-000203)
  tag gid: 'V-VRPA-8X-000003'
  tag rid: 'SV-VRPA-8X-000003'
  tag stig_id: 'VRPA-8X-000003'
  tag cci: %w(CCI-001348 CCI-001844 CCI-001851 CCI-001876)
  tag nist: ['AU-3 (2)', 'AU-4 (1)', 'AU-7 a', 'AU-9 (2)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
