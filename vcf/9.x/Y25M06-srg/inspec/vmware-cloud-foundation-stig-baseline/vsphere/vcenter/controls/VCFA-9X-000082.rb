control 'VCFA-9X-000082' do
  title 'The VMware Cloud Foundation vCenter Server must terminate sessions after 15 minutes of inactivity.'
  desc  "
    Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. This does not mean that the application terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Deployment >> Client Configuration.

    View the value of the \"Session timeout\" setting.

    If the \"Session timeout\" is not set to \"15 minute(s)\" or less, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Deployment >> Client Configuration.

    Click \"Edit\" and enter \"15\" minutes into the \"Session timeout\" setting. Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000190'
  tag satisfies: ['SRG-APP-000295']
  tag gid: 'V-VCFA-9X-000082'
  tag rid: 'SV-VCFA-9X-000082'
  tag stig_id: 'VCFA-9X-000082'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['AC-12', 'SC-10']

  describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
    skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
  end
end
