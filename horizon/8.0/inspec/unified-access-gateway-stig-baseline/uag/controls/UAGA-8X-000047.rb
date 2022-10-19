control 'UAGA-8X-000047' do
  title 'The UAG must terminate all network connections associated with a user session at the end of the session.'
  desc  "
    Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system level network connection.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to edit.

    If the \"Session Timeout\" is not configured within the organization defined permitted time limit (default is 10 hours), this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to edit.

    Set the \"Session Timeout\" value to \"36000000\" (10 hours).

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000213-ALG-000107'
  tag satisfies: ['SRG-NET-000344-ALG-000098', 'SRG-NET-000517-ALG-000006']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000047'
  tag cci: ['CCI-001133', 'CCI-002007', 'CCI-002361']
  tag nist: ['AC-12', 'IA-5 (13)', 'SC-10']

  result = uaghelper.runrestcommand('rest/v1/config/settings')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe jsoncontent do
      its(['systemSettings', 'sessionTimeout']) { should cmp input('sessionTimeoutMilliseconds') }
    end
  end
end
