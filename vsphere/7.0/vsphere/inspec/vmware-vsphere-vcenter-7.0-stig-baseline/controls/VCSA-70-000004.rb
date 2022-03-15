control 'VCSA-70-000004' do
  title "The vCenter Server must terminate vSphere Client sessions after 10
minutes of inactivity."
  desc  "Terminating an idle session within a short time period reduces the
window of opportunity for unauthorized personnel to take control of a
management session enabled on the console or console port that has been left
unattended. In addition, quickly terminating an idle session will also free up
resources committed by the managed network element."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Deployment >> Client
Configuration. View the value of the \"Session timeout\" setting.

    If the \"Session timeout\" is not set to \"10 minute(s)\", or below, this
is a finding.
  "
  desc 'fix', "From the vSphere Client, go to Administration >> Deployment >>
Client Configuration. Click \"Edit\" and enter \"10\" minutes into the
\"Session timeout\" setting. Click \"Save\". "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000190'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000004'
  tag fix_id: nil
  tag cci: 'CCI-001133'
  tag nist: ['SC-10']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
