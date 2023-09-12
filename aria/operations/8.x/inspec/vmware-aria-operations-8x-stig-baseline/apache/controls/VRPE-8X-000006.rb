control 'VRPE-8X-000006' do
  title 'The vRealize Operations Manager Apache server files must be verified for their integrity (e.g., checksums and hashes) before becoming part of the production web server.'
  desc  "
    Being able to verify that a patch, upgrade, certificate, etc., being added to the web server is unchanged from the producer of the file is essential for file validation and non-repudiation of the information.

    The web server or hosting system must have a mechanism to verify that files, before installation, are valid.

    Examples of validation methods are sha1 and md5 hashes and checksums.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # rpm -V httpd | grep \"/usr/\" | grep -v \"httpd.service\"

    If the command produces any output, this is a finding.
  "
  desc 'fix', "
    Roll back to a previous snapshot, restore from backup or deploy a new node and retire the affected one.

    There is no way to repair the Apache binaries post-deployment since the source rpms are no longer present.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag gid: 'V-VRPE-8X-000006'
  tag rid: 'SV-VRPE-8X-000006'
  tag stig_id: 'VRPE-8X-000006'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('rpm -V httpd | grep "/usr/" | grep -v "httpd.service"') do
    its('stdout.strip') { should cmp '' }
  end
end
