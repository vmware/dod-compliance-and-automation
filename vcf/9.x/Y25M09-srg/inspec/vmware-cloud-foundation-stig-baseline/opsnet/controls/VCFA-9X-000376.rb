control 'VCFA-9X-000376' do
  title 'VMware Cloud Foundation Operations for Networks must terminate sessions after 15 minutes of inactivity.'
  desc  "
    Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. This does not mean that the application terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Networks is not deployed, this is not applicable.

    From VCF Operations for Networks, go to Settings >> System Configuration.

    Review the value of the \"User Session timeout\" setting.

    If the \"User Session timeout\" is not set to \"15 minute(s)\" or less, this is a finding.
  "
  desc 'fix', "
    From VCF Operations for Networks, go to Settings >> System Configuration.

    Click \"Edit\" next to \"User Session timeout\" setting. Enter a timeout of 15 minutes or less and click \"Submit\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000190'
  tag gid: 'V-VCFA-9X-000376'
  tag rid: 'SV-VCFA-9X-000376'
  tag stig_id: 'VCFA-9X-000376'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  if input('opsnet_deployed')
    describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
      skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
    end
  else
    impact 0.0
    describe 'VCF Operations for Networks is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations for Networks is not deployed in the target environment. This control is N/A.'
    end
  end
end
