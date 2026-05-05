control 'VCFA-9X-000292' do
  title 'VMware Cloud Foundation Operations must disable unsigned management pack installation.'
  desc  "
    Software and firmware components prevented from installation unless signed with recognized and approved certificates include software and firmware version updates, patches, service packs, device drivers, and basic input/output system updates.

    This option permits the installation of PAK files without signature verification. Enabling it may pose security risks, as unsigned files could contain untrusted content.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the admin portal (/admin/) as an administrator.

    Go to Administrator Settings >> Security Settings.

    View the status of \"Allow unsigned PAK installation\".

    If \"Allow unsigned PAK installation\" is enabled, this is a finding.
  "
  desc 'fix', "
    Disabling unsigned PAK installation must be done from the admin portal. Login to the admin portal (/admin/) as an administrator.

    Go to Administrator Settings >> Security Settings.

    Click the \"Disable unsigned PAK installation\" button.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000810'
  tag gid: 'V-VCFA-9X-000292'
  tag rid: 'SV-VCFA-9X-000292'
  tag stig_id: 'VCFA-9X-000292'
  tag cci: ['CCI-003992']
  tag nist: ['CM-14']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
