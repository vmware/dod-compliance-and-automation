control 'V-219155' do
  title "Advance package Tool (APT) must be configured to prevent the installation
    of patches, service packs, device drivers, or Ubuntu operating system components
    without verification they have been digitally signed using a certificate that is
    recognized and approved by the organization."
  desc  "Changes to any software components can have significant effects on the
    overall security of the Ubuntu operating system. This requirement ensures the
    software has not been tampered with and that it has been provided by a trusted
    vendor.

    Accordingly, patches, service packs, device drivers, or Ubuntu operating
    system components must be signed with a certificate recognized and approved by
    the organization.

    Verifying the authenticity of the software prior to installation validates
    the integrity of the patch or upgrade received from a vendor. Setting the
    \"Verify-Peer\" Boolean will determine whether or not the server's host
    certificate should be verified against trusted certificates. This ensures the
    software has not been tampered with and that it has been provided by a trusted
    vendor. Self-signed certificates are disallowed by this requirement. The Ubuntu
    operating system should not have to verify the software again. This requirement
    does not mandate DoD certificates for this purpose; however, the certificate
    used to verify the software must be from an approved CA.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000366-GPOS-00153"
  tag "gid": 'V-219155'
  tag "rid": "SV-219155r379825_rule"
  tag "stig_id": "UBTU-18-010016"
  tag "fix_id": "F-20879r304794_fix"
  tag "cci": [ "CCI-001749" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify that Advance package Tool (APT) is configured to prevent the
    installation of patches, service packs, device drivers, or Ubuntu operating system
    components without verification they have been digitally signed using a certificate
    that is recognized and approved by the organization.

    Check that the \"AllowUnauthenticated\" variable is not set at all or set to \"false\"
    with the following command:

    # grep AllowUnauthenticated /etc/apt/apt.conf.d/*
    /etc/apt/apt.conf.d/01-vendor-Ubuntu:APT::Get::AllowUnauthenticated \"false\";

    If any of the files returned from the command with \"AllowUnauthenticated\" set to
    \"true\", this is a finding.
  "

  desc 'fix', "Configure Advance package Tool (APT) to prevent the installation of patches,
    service packs, device drivers, or Ubuntu operating system components without verification
    they have been digitally signed using a certificate that is recognized and approved by
    the organization.

    Remove/Update any APT configuration file that contain the variable \"AllowUnauthenticated\"
     to \"false\", or remove \"AllowUnauthenticated\" entirely from each file.
     Below is an example of setting the \"AllowUnauthenticated\" variable to \"false\":

    APT::Get::AllowUnauthenticated \"false\";
  "
  describe directory('/etc/apt/apt.conf.d') do
    it { should exist }
  end

  apt_allowunauth = command('grep -i allowunauth /etc/apt/apt.conf.d/*').stdout.strip.split("\n")
  if apt_allowunauth.empty?
    describe 'apt conf files do not contain AllowUnauthenticated' do
      subject { apt_allowunauth.empty? }
      it { should be true }
    end
  else
    apt_allowunauth.each do |line|
      describe "#{line} contains AllowUnauthenctication" do
        subject { line }
        it { should_not match /.*false.*/ }
      end
    end
  end
end
