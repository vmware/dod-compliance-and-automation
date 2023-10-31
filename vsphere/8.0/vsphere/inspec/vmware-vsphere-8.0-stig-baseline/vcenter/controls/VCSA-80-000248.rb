control 'VCSA-80-000248' do
  title 'The vCenter Server must disable the Customer Experience Improvement Program (CEIP).'
  desc  'The VMware CEIP sends VMware anonymized system information that is used to improve the quality, reliability, and functionality of VMware products and services. For confidentiality purposes, this feature must be disabled.'
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Deployment >> Customer Experience Improvement Program.

    If Customer Experience Improvement \"Program Status\" is \"Joined\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Deployment >> Customer Experience Improvement Program.

    Click \"Leave Program\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCSA-80-000248'
  tag rid: 'SV-VCSA-80-000248'
  tag stig_id: 'VCSA-80-000248'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
