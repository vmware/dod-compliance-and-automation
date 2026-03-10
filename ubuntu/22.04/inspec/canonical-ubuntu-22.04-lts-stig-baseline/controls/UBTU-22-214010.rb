control 'UBTU-22-214010' do
  title 'Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) prevents the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DOD certificates for this purpose; however, the certificate used to verify the software must be from an approved certificate authority (CA).'
  desc 'check', 'Verify that APT is configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization by using the following command:

     $ grep -i allowunauthenticated /etc/apt/apt.conf.d/*
     /etc/apt/apt.conf.d/01-vendor-ubuntu:APT::Get::AllowUnauthenticated "false";

If "APT::Get::AllowUnauthenticated" is not set to "false", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure APT to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.

Add or modify the following line in any file under the "/etc/apt/apt.conf.d/" directory:

APT::Get::AllowUnauthenticated "false";'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64205r953239_chk'
  tag severity: 'low'
  tag gid: 'V-260476'
  tag rid: 'SV-260476r1015003_rule'
  tag stig_id: 'UBTU-22-214010'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-64113r953240_fix'
  tag 'documentable'
  tag cci: ['CCI-003992', 'CCI-001749']
  tag nist: ['CM-14', 'CM-5 (3)']

  aptconf = command('apt-config dump').stdout
  options = {
    # Parses key value pairs as beginning of line to space then the value inside of quotes
    assignment_regex: /^([^=]*?)\s"(.*?)";$/
  }
  describe parse_config(aptconf, options) do
    its('APT::Get::AllowUnauthenticated') { should cmp false }
  end
end
