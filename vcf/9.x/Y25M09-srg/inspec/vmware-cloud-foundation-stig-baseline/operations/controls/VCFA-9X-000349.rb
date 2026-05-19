control 'VCFA-9X-000349' do
  title 'VMware Cloud Foundation Operations must terminate sessions after 15 minutes of inactivity.'
  desc  "
    Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. This does not mean that the application terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.
  "
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Administration >> Global Settings >> System Settings.

    View the value of the \"Session Inactivity Timeout\" setting.

    If the \"Session Inactivity Timeout\" is not set to 15 minutes or less, this is a finding.
  "
  desc 'fix', "
    From VCF Operations, go to Administration >> Global Settings >> System Settings.

    Update the value for the \"Session Inactivity Timeout\" setting to 15 and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000190'
  tag gid: 'V-VCFA-9X-000349'
  tag rid: 'SV-VCFA-9X-000349'
  tag stig_id: 'VCFA-9X-000349'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  response = http("https://#{input('operations_apihostname')}/suite-api/api/deployment/config/globalsettings",
                  method: 'GET',
                  ssl_verify: false,
                  headers: { 'Content-Type' => 'application/json',
                             'Accept' => 'application/json',
                             'Authorization' => "OpsToken #{input('operations_apitoken')}" })

  describe response do
    its('status') { should cmp 200 }
  end

  unless response.status != 200
    keyvals = json(content: response.body)['keyValues']
    itemkey = keyvals.find { |item| item['key'] == 'SESSION_TIMEOUT_IN_MINUTES' }

    if itemkey
      describe 'Session Timeout must be configured for 15 minutes' do
        subject { itemkey['values'] }
        it { should eq ['15'] }
      end
    else
      describe 'Session Timeout key' do
        subject { itemkey }
        it { should_not be_nil }
      end
    end
  end
end
