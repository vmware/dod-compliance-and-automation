control 'VCSA-80-000089' do
  title 'The vCenter Server must terminate vSphere Client sessions after 15 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free resources committed by the managed network element.

'
  desc 'check', 'From the vSphere Client, go to Administration >> Deployment >> Client Configuration.

View the value of the "Session timeout" setting.

If the "Session timeout" is not set to "15 minute(s)" or less, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Deployment >> Client Configuration.

Click "Edit" and enter "15" minutes into the "Session timeout" setting. Click "Save".'
  impact 0.5
  tag check_id: 'C-62660r934416_chk'
  tag severity: 'medium'
  tag gid: 'V-258920'
  tag rid: 'SV-258920r1003601_rule'
  tag stig_id: 'VCSA-80-000089'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-62569r934417_fix'
  tag satisfies: ['SRG-APP-000190', 'SRG-APP-000295', 'SRG-APP-000389']
  tag cci: ['CCI-001133', 'CCI-004895', 'CCI-002361']
  tag nist: ['SC-10', 'SC-11 b', 'AC-12']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
