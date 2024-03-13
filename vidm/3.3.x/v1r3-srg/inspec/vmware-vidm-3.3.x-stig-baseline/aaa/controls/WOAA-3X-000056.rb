control 'WOAA-3X-000056' do
  title 'Workspace ONE Access must be configured to send audit records to a centralized audit server.'
  desc  'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Off-loading is a common process in information systems with limited audit storage capacity.'
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>:8443/cfg\" using administrative credentials.

    Click \"Configure Syslog\" in the left pane to view the current syslog configuration.

    If syslog is not enabled, this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>:8443/cfg\" using administrative credentials.

    Click \"Configure Syslog\" in the left pane.

    Select Enable and specify a syslog server destination and protocol then click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-AAA-000280'
  tag gid: 'V-WOAA-3X-000056'
  tag rid: 'SV-WOAA-3X-000056'
  tag stig_id: 'WOAA-3X-000056'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
