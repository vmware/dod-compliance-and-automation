control 'UAGA-8X-000086' do
  title 'The UAG must be configured to support centralized management of audit records and logs.'
  desc  "
    Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

    The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. The UAG provides several transport methods for offloading logs to a centralized syslog server.

    The DoD requires centralized management of all network component audit records. This requirement does not apply to audit logs generated on behalf of the device itself (management).
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> Syslog Server Settings.

    Click the \"Gear\" icon to edit.

    Verify that at least one syslog server has been added.

    If no offloading of audit records has been configured, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> Syslog Server Settings.

    Click the \"Gear\" icon to edit.

    Click \"Add Syslog Entry\", select the desired protocol and fill in all required fields.

    Click \"Add\" then \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000333-ALG-000049'
  tag satisfies: ['SRG-NET-000334-ALG-000050', 'SRG-NET-000511-ALG-000051']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000086'
  tag cci: ['CCI-001844', 'CCI-001851']
  tag nist: ['AU-3 (2)', 'AU-4 (1)']

  result = uaghelper.runrestcommand('rest/v1/config/settings')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)

    describe jsoncontent['syslogSettings']['syslogServerSettings'] do
      it { should_not cmp nil }
    end
  end
end
