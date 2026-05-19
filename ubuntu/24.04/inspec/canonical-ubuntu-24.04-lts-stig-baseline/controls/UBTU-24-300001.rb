control 'UBTU-24-300001' do
  title 'Ubuntu 24.04 LTS Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu 24.04 LTS components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of Ubuntu 24.04 LTS. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. Ubuntu 24.04 LTS will not have to verify the software again. This requirement does not mandate DOD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Verify that APT is configured to prevent the installation of patches, service packs, device drivers, or Ubuntu 24.04 LTS components without verification they have been digitally signed using a certificate recognized and approved by the organization with the following command:

$ grep AllowUnauthenticated /etc/apt/apt.conf.d/*

If any files are returned from the command with "AllowUnauthenticated" are set to "true", this is a finding.'
  desc 'fix', 'Configure APT to prevent the installation of patches, service packs, device drivers, or Ubuntu 24.04 LTS components without verification they have been digitally signed using a certificate recognized and approved by the organization.

Remove/update any APT configuration files that contain the variable "AllowUnauthenticated" to "false" or remove "AllowUnauthenticated" entirely from each file. Below is an example of setting the "AllowUnauthenticated" variable to "false":

APT::Get::AllowUnauthenticated "false";'
  impact 0.3
  tag check_id: 'C-74728r1066572_chk'
  tag severity: 'low'
  tag gid: 'V-270695'
  tag rid: 'SV-270695r1066574_rule'
  tag stig_id: 'UBTU-24-300001'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-74629r1066573_fix'
  tag 'documentable'
  tag cci: ['CCI-003992']
  tag nist: ['CM-14']

  aptconf = command('apt-config dump').stdout
  options = {
    # Parses key value pairs as beginning of line to space then the value inside of quotes
    assignment_regex: /^([^=]*?)\s"(.*?)";$/
  }
  describe.one do
    describe parse_config(aptconf, options) do
      its('APT::Get::AllowUnauthenticated') { should cmp false }
    end
    describe parse_config(aptconf, options) do
      its('APT::Get::AllowUnauthenticated') { should_not be_present }
    end
  end
end
