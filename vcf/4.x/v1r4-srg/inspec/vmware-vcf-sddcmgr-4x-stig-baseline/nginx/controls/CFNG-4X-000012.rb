control 'CFNG-4X-000012' do
  title 'The SDDC Manager NGINX service files must be verified for their integrity.'
  desc  'Being able to verify that a patch, upgrade, certificate, etc., being added to the web server is unchanged from the producer of the file is essential for file validation and non-repudiation of the information.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # rpm -V nginx|grep \"^..5......\"|grep -v \"\\.conf\"

    If there is any output, this is a finding.
  "
  desc 'fix', 'Investigate any returned files and re-install NGINX if necessary.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag gid: 'V-CFNG-4X-000012'
  tag rid: 'SV-CFNG-4X-000012'
  tag stig_id: 'CFNG-4X-000012'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('rpm -V nginx|grep \"^..5......\"|grep -v \"\.conf\"') do
    its('stdout.strip') { should eq '' }
  end
end
