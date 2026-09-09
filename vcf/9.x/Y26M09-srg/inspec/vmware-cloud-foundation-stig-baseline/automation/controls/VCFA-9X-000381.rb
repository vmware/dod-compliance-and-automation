control 'VCFA-9X-000381' do
  title 'VMware Cloud Foundation Automation assigned roles and permissions must be verified.'
  desc  'Users and service accounts must only be assigned privileges they require. Least privilege requires that these privileges must only be assigned if needed to reduce risk of confidentiality, availability, or integrity loss.'
  desc  'rationale', ''
  desc  'check', "
    If VCF Automation is not deployed, this is not applicable.

    From the VCF Automation Provider interface, go to Administration >> Access Control.

    Review the users, groups, and service accounts tabs and their assigned roles.

    If any user, group, or service account has more privileges than required, this is a finding.
  "
  desc 'fix', "
    To update a user's or group's permissions to a role with reduced permissions, do the following:

    From the VCF Automation Provider interface, go to Administration >> Access Control.

    For the target the user or group, click the menu button on the left and select \"Edit\".

    Update or remove roles from the \"Role\" drop down menu and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211'
  tag gid: 'V-VCFA-9X-000381'
  tag rid: 'SV-VCFA-9X-000381'
  tag stig_id: 'VCFA-9X-000381'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  if input('automation_deployed')
    describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
      skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
    end
  else
    impact 0.0
    describe 'VCF Automation is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Automation is not deployed in the target environment. This control is N/A.'
    end
  end
end
