control 'PHTN-50-000066' do
  title 'The Photon operating system must enable SELinux.'
  desc  "
    An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

    Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from nonsecurity functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For nonkernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

    Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Operating systems restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify SELinux is enabled:

    # getenforce

    Expected result:

    Enforcing

    If SELinux is not active and not in \"Enforcing\" mode, this is a finding.

    Note: The \"getenforce\" command requires the \"libselinux-utils\" package to be installed.
  "
  desc 'fix', "
    Navigate to and open:

    /boot/grub2/grub.cfg

    Locate the boot command line arguments. An example follows:

    linux /boot/$photon_linux root=$rootpartition $photon_cmdline $systemd_cmdline

    Add \"security=selinux selinux=1 enforcing=1\" to the end of the line so it reads as follows:

    linux /boot/$photon_linux root=$rootpartition $photon_cmdline $systemd_cmdline audit=1 security=selinux selinux=1 enforcing=1

    Note: Do not copy/paste in this example argument line. This may change in future releases. Find the similar line and append \"security=selinux selinux=1 enforcing=1\" to it.

    Reboot the system for the change to take effect.

    Note: The selinux-policy package must be installed before these steps can be completed.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag satisfies: ['SRG-OS-000445-GPOS-00199']
  tag gid: 'V-PHTN-50-000066'
  tag rid: 'SV-PHTN-50-000066'
  tag stig_id: 'PHTN-50-000066'
  tag cci: ['CCI-001084', 'CCI-002696']
  tag nist: ['SC-3', 'SI-6 a']

  describe selinux do
    it { should be_installed }
    it { should_not be_disabled }
    it { should be_enforcing }
  end
end
