control 'VCLD-70-000009' do
  title 'VAMI server binaries and libraries must be verified for their integrity.'
  desc  "
    Being able to verify that a patch, upgrade, certificate, etc., being added to the web server is unchanged from the producer of the file is essential for file validation and non-repudiation of the information.

    VMware delivers product updates and patches regularly. When VAMI is updated, the signed packages will also be updated. These packages can be used to verify that VAMI has not been inappropriately modified since it was installed.

    The file \"lighttpd.conf\" and \"vami-lighttp.service\" are intentionally modified on first boot and thus are excluded from the check.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # rpm -qa|grep lighttpd|xargs rpm -V|grep -v -E \"lighttpd.conf|vami-lighttp.service\"

    If the command returns any output, this is a finding.
  "
  desc 'fix', "
    If the VAMI binaries have been modified from the default state when deployed as part of the VCSA then the system must be wiped and redeployed or restored from backup.

    VMware does not recommend or support recovering from such a state by reinstalling RPMs or similar efforts.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag satisfies: ['SRG-APP-000211-WSR-000030', 'SRG-APP-000380-WSR-000072']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000009'
  tag cci: ['CCI-001082', 'CCI-001749', 'CCI-001813']
  tag nist: ['CM-5 (1)', 'CM-5 (3)', 'SC-2']

  describe command('rpm -V vmware-studio-vami-lighttpd|grep "^..5......"|grep -v -E "\.conf|\.service"') do
    its('stdout.strip') { should eq '' }
  end
end
