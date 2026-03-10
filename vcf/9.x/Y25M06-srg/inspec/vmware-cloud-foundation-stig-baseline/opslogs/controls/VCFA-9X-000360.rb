control 'VCFA-9X-000360' do
  title 'VMware Cloud Foundation Operations for Logs assigned roles and permissions must be verified.'
  desc  'Users and service accounts must only be assigned privileges they require. Least privilege requires that these privileges must only be assigned if needed to reduce risk of confidentiality, availability, or integrity loss.'
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Logs is not deployed, this is not applicable.

    From VCF Operations for Logs, go to Management >> Access Control.

    Verify assigned roles by reviewing each user.

    If any user or service account has more privileges than required, this is a finding.
  "
  desc 'fix', "
    To update a user's or group's permissions to an existing role with reduced permissions, do the following:

    From VCF Operations for Logs, go to Management >> Access Control.

    Click Edit next to the target user.

    Assign the appropriate role with the least privilege necessary and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211'
  tag gid: 'V-VCFA-9X-000360'
  tag rid: 'SV-VCFA-9X-000360'
  tag stig_id: 'VCFA-9X-000360'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  if input('opslogs_deployed')
    describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
      skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
    end
  else
    impact 0.0
    describe 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.'
    end
  end
end
