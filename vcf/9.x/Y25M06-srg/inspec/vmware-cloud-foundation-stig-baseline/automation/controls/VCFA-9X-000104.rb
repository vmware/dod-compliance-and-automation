control 'VCFA-9X-000104' do
  title 'VMware Cloud Foundation Automation must restrict the ability of individuals to use information systems to launch denial-of-service (DoS) attacks against other information systems.'
  desc  "
    DoS is a condition in which a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

    Individuals of concern can include hostile insiders or external adversaries that have successfully breached the information system and are using the system as a platform to launch cyberattacks on third parties.

    Applications and application developers must take the steps needed to ensure users cannot use an authorized application to launch DoS attacks against other systems and networks. For example, applications may include mechanisms that throttle network traffic so users are not able to generate unlimited network traffic via the application. Limiting system resources allocated to any user to a bare minimum may also reduce the ability of users to launch some DoS attacks.

    The methods employed to counter this risk will be dependent upon the application layer methods that can be used to exploit it.
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Automation is not deployed, this is not applicable.

    From the VCF Automation Provider interface, go to Administration >> General Settings.

    Review the \"Operation Limits\" settings and verify resource intensive operations are not unlimited.

    If any resource intensive operation limit is set to unlimited, this is a finding.
  "
  desc 'fix', "
    From the VCF Automation Provider interface, go to Administration >> General Settings.

    Click \"Edit\" on the \"Operation Limits\" pane.

    Uncheck unlimited for each resource intensive operation limit and enter a new limit between 1 and 100000 for each setting then click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000246'
  tag gid: 'V-VCFA-9X-000104'
  tag rid: 'SV-VCFA-9X-000104'
  tag stig_id: 'VCFA-9X-000104'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

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
