control 'VRAA-8X-000012' do
  title 'VMware Aria Automation must use only DoD approved certificates.'
  desc  'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNSS creates an integrity risk. The application server must utilize approved DoD or CNSS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc  'rationale', ''
  desc  'check', "
    At the command line interface run the following command:

    # vracli certificate ingress --parse

    If the certificate is not an approved DoD issued certificate, this is a finding.
  "
  desc 'fix', "
    VMware Aria Lifecycle Manager manages day 2 operations for VMware Aria Automation, and it should be used to replace certificates.

    A suitable DoD issued certificate should be imported into VMware Aria Lifecycle Manager before performing these steps.

    Log in to VMware Aria Lifecycle Manager as an administrative user.

    Select Lifecycle Operations >> Environments.

    Select the environment which contains the VMware Aria Automation deployment and then select the VMware Aria Automation deployment.

    Click Replace Certificate, select the imported DoD issued certificate, and click Submit.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag satisfies: ['SRG-APP-000427-AS-000264']
  tag gid: 'V-VRAA-8X-000012'
  tag rid: 'SV-VRAA-8X-000012'
  tag stig_id: 'VRAA-8X-000012'
  tag cci: ['CCI-002450', 'CCI-002470']
  tag nist: ['SC-13', 'SC-23 (5)']

  describe json({ command: 'vracli certificate ingress --parse' }) do
    its(['chain', 1, 'basic_details', 'issuer', 'components', 1]) { should cmp ['O', 'U.S. Government'] }
  end
end
