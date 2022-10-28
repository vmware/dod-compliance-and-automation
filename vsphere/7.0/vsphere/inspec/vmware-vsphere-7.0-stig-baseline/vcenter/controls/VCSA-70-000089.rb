control 'VCSA-70-000089' do
  title 'The vCenter Server must terminate vSphere Client sessions after 10 minutes of inactivity.'
  desc  'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Deployment >> Client Configuration.

    View the value of the \"Session timeout\" setting.

    If the \"Session timeout\" is not set to \"10 minute(s)\", or below, this is a finding.

    Note: If vCenter is not 7.0 U2 or newer this setting is not available through the UI and must be checked with the \"session.timeout\" setting in the /etc/vmware/vsphere-ui/webclient.properties file.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Deployment >> Client Configuration.

    Click \"Edit\" and enter \"10\" minutes into the \"Session timeout\" setting. Click \"Save\".

    Note: If vCenter is not 7.0 U2 or newer this setting is not available through the UI and must be fixed with the \"session.timeout\" setting in the /etc/vmware/vsphere-ui/webclient.properties file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000190'
  tag satisfies: ['SRG-APP-000295', 'SRG-APP-000389']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000089'
  tag cci: ['CCI-001133', 'CCI-002038', 'CCI-002361']
  tag nist: ['AC-12', 'IA-11', 'SC-10']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
