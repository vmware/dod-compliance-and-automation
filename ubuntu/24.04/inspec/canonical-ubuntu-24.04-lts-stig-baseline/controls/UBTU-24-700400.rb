control 'UBTU-24-700400' do
  title 'Ubuntu 24.04 LTS must be a vendor-supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

The support status of the OS depends on its subscription status.

End Of Life dates for Ubuntu 24.04 releases are as follows:
Standard Support: April 2029
Extended Security Maintenance (ESM): April 2036

ESM is available via an Ubuntu Pro subscription.'
  desc 'check', 'Verify the version of Ubuntu 24.04 LTS is vendor supported with the following command:

$ grep DISTRIB_DESCRIPTION /etc/lsb-release
DISTRIB_DESCRIPTION="Ubuntu 24.04.3 LTS"

Check the subscription status of the system with the following command:
$ pro status

If the installed version of Ubuntu 24.04 LTS is not supported, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of Ubuntu 24.04 LTS.'
  impact 0.7
  tag check_id: 'C-83451r1155233_chk'
  tag severity: 'high'
  tag gid: 'V-278917'
  tag rid: 'SV-278917r1155246_rule'
  tag stig_id: 'UBTU-24-700400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-83356r1134999_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This is a manual check as ubuntu pro subscription is required to check for status.' do
    skip 'This is a manual check as ubuntu pro subscription is required to check for status.'
  end
end
