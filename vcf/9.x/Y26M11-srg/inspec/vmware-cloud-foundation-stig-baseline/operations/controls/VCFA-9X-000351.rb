control 'VCFA-9X-000351' do
  title 'VMware Cloud Foundation Operations assigned roles and scopes must be verified.'
  desc  'Users and service accounts must only be assigned privileges they require. Least privilege requires that these privileges must only be assigned if needed to reduce risk of confidentiality, availability, or integrity loss.'
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Administration >> Control Panel >> Access Control.

    Verify assigned roles and scopes by reviewing each user and group.

    If any user or service account has more privileges or access to more objects than required, this is a finding.
  "
  desc 'fix', "
    To delete a user or group from VCF Operations, do the following:

    From VCF Operations, go to Administration >> Control Panel >> Access Control.

    Select the user or group that is no longer required and click Delete.

    Click Yes to verify deletion.


    To update a user's or group's role and scope from VCF Operations, do the following:

    From VCF Operations, go to Administration >> Control Panel >> Access Control.

    Select the user or group with excess privileges and click Edit.

    Update the assigned roles and scopes and click Save.


    To update permissions assigned to a role in VCF Operations, do the following:

    From VCF Operations, go to Administration >> Control Panel >> Access Control >> Roles.

    Select the target role and click Edit.

    Remove any unneeded permissions and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211'
  tag gid: 'V-VCFA-9X-000351'
  tag rid: 'SV-VCFA-9X-000351'
  tag stig_id: 'VCFA-9X-000351'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
    skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
  end
end
