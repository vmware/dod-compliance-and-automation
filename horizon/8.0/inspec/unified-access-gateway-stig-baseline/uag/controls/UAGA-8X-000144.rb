control 'UAGA-8X-000144' do
  title 'The UAG must initiate a session lock after a 15-minute period of inactivity.'
  desc  "
    A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their session prior to vacating the vicinity, network elements need to be able to identify when a user's session has gone idle and take action to initiate the session lock.

    The session lock must be implemented at the point where session activity can be determined and/or controlled.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    If the \"Client Connection Idle Timeout\" option is not configured, has a value of 0, or has a value larger than 900, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Set the \"Client Connection Idle Timeout\" value to 900.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000514-ALG-000514'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000144'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']

  result = uaghelper.runrestcommand('rest/v1/config/settings')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe jsoncontent do
      its(['systemSettings', 'clientConnectionIdleTimeout']) { should be <= 900 }
    end
  end
end
