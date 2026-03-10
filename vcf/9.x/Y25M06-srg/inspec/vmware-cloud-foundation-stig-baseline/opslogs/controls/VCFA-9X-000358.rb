control 'VCFA-9X-000358' do
  title 'VMware Cloud Foundation Operations for Logs must terminate sessions after 15 minutes of inactivity.'
  desc  "
    Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. This does not mean that the application terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Logs is not deployed, this is not applicable.

    From VCF Operations for Logs, go to Configuration >> General.

    Review the \"Session Timeout\" configuration.

    If \"Session Timeout\" is not configured to 15 minutes or less and not greater than 0, this is a finding.
  "
  desc 'fix', "
    From VCF Operations for Logs, go to Configuration >> General.

    Under \"Browser Session\" update the \"Session Timeout\" to 15 and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000190'
  tag gid: 'V-VCFA-9X-000358'
  tag rid: 'SV-VCFA-9X-000358'
  tag stig_id: 'VCFA-9X-000358'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  if input('opslogs_deployed')
    response = http("https://#{input('opslogs_apihostname')}/api/v2/ui/browser-session",
                    method: 'GET',
                    ssl_verify: false,
                    headers: { 'Content-Type' => 'application/json',
                               'Accept' => 'application/json',
                               'Authorization' => "Bearer #{input('opslogs_apitoken')}" })

    describe response do
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      responseval = json(content: response.body)['timeout']

      if responseval
        describe 'Session termination' do
          subject { responseval }
          it { should cmp 15 }
        end
      else
        describe 'Session termination' do
          subject { responseval }
          it { should_not be_nil }
        end
      end
    end
  else
    impact 0.0
    describe 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.'
    end
  end
end
