control 'VCFA-9X-000380' do
  title 'VMware Cloud Foundation Operations for Networks assigned roles and permissions must be verified.'
  desc  'Users and service accounts must only be assigned privileges they require. Least privilege requires that these privileges must only be assigned if needed to reduce risk of confidentiality, availability, or integrity loss.'
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Networks is not deployed, this is not applicable.

    From VCF Operations for Networks, go to Settings >> Identity and Access Management >> User Management.

    Review each user's assigned role.

    If any user or service account has more privileges than required, this is a finding.
  "
  desc 'fix', "
    To update a user's or group's permissions to a role with reduced permissions, do the following:

    From VCF Operations for Networks, go to Settings >> Identity and Access Management >> User Management.

    For the target the user or group, click the pencil button to edit the role.

    Select the new role from the \"Role\" drop down menu and click \"Submit\".

    To delete a user or group that does not need access, do the following:

    From VCF Operations for Networks, go to Settings >> Identity and Access Management >> User Management.

    For the target the user or group, click the delete icon and click \"Continue\" to delete.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211'
  tag gid: 'V-VCFA-9X-000380'
  tag rid: 'SV-VCFA-9X-000380'
  tag stig_id: 'VCFA-9X-000380'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

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
