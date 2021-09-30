# encoding: UTF-8

control 'VCST-70-000008' do
  title "The Security Token Service application files must be verified for
their integrity."
  desc  "Verifying that the Security Token Service application code is
unchanged from it's shipping state is essential for file validation and
non-repudiation of the Security Token Service. There is no reason that the MD5
hash of the rpm original files should be changed after installation, excluding
configuration files."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -V vmware-identity-sts|grep \"^..5......\"|grep -v -E
\"\\.properties|\\.xml\"

    If is any output, this is a finding.
  "
  desc  'fix', "
    Re-install the VCSA or roll back to a backup.

    Modifying the Security Token Service installation files manually is not
supported by VMware.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000008'
  tag fix_id: nil
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  describe command('rpm -V vmware-identity-sts|grep "^..5......"|grep -v -E "\.properties|\.xml"') do
    its ('stdout.strip') { should eq '' }
  end

end

