control 'NALB-CO-000052' do
  title 'The NSX Advanced Load Balancer Controller must terminate all network connections associated with a device management session after 10 minutes of inactivity.'
  desc  "
    Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.
  "
  desc  'rationale', ''
  desc  'check', "
    Review if the NSX-ALB terminates the connection associated with a device management session after 10 minutes of inactivity.

    From the NSX ALB Controller web interface on top right-hand side, click on the User Icon >> My Account.

    If \"Session Timeout\" value is not set to 10 or less, this is a finding.
  "
  desc 'fix', "
    To modify the global value \"Session Timeout\" do the following.

    From the NSX ALB Controller web interface on top right-hand side, click on the User Icon >> My Account.

    Update the \"Session Timeout\" value to 10 and click Save.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag satisfies: ['SRG-APP-000186-NDM-000266', 'SRG-APP-000400-NDM-000313']
  tag gid: 'V-NALB-CO-000052'
  tag rid: 'SV-NALB-CO-000052'
  tag stig_id: 'NALB-CO-000052'
  tag cci: ['CCI-000879', 'CCI-001133', 'CCI-002007']
  tag nist: ['IA-5 (13)', 'MA-4 e', 'SC-10']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
