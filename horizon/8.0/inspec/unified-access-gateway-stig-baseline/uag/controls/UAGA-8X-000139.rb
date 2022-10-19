control 'UAGA-8X-000139' do
  title 'The UAG must offload system level log information to a centralized server.'
  desc  "
    Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

    The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. The UAG provides options for offloading logs to a centralized syslog server, including an option to send system-level log information.

    The DoD requires centralized management of all network component audit record content.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> Syslog Server Settings.

    Click the \"Gear\" icon to edit.

    Verify that the \"Syslog Include System Messages\" toggle is enabled.

    If the \"Syslog Include System Messages\" toggle is not enabled, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> Syslog Server Settings.

    Click the \"Gear\" icon to edit.

    Ensure the \"Syslog Include System Messages\" toggle is enabled.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000139'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = uaghelper.runrestcommand('rest/v1/config/settings')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)

    describe jsoncontent['syslogSettings']['syslogSystemMessagesEnabled'] do
      it { should cmp true }
    end
  end
end
