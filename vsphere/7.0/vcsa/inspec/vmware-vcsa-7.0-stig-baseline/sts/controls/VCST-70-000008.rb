control 'VCST-70-000008' do
  title 'The Security Token Service application files must be verified for their integrity.'
  desc  'Verifying the Security Token Service application code is unchanged from its shipping state is essential for file validation and nonrepudiation of the Security Token Service. There is no reason the MD5 hash of the RPM original files should be changed after installation, excluding configuration files.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # rpm -V vmware-identity-sts|grep \"^..5......\"|grep -v -E \"\\.properties|\\.xml|\\.conf\"

    If is any output, this is a finding.
  "
  desc 'fix', "
    Reinstall the vCenter Server Appliance (VCSA) or roll back to a backup.

    VMware does not support modifying the Security Token Service installation files manually.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag satisfies: ['SRG-APP-000357-WSR-000150']
  tag gid: 'V-256752'
  tag rid: 'SV-256752r889226_rule'
  tag stig_id: 'VCST-70-000008'
  tag cci: ['CCI-001749', 'CCI-001849']
  tag nist: ['AU-4', 'CM-5 (3)']

  describe command('rpm -V vmware-identity-sts|grep "^..5......"|grep -v -E "\.properties|\.xml|\.conf"') do
    its('stdout.strip') { should eq '' }
  end
end
