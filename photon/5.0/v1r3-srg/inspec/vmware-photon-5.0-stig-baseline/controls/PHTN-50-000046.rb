control 'PHTN-50-000046' do
  title 'The Photon operating system must require authentication upon booting into single-user and maintenance modes.'
  desc  "
    If the system does not require authentication before it boots into single-user mode, anyone with console access to the system can trivially access all files on the system. GRUB2 is the boot loader for Photon OS and can be configured to require a password to boot into single-user mode or make modifications to the boot menu.

    Note: Photon does not support building grub changes via grub2-mkconfig.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify a password is required to edit the grub bootloader to boot into single-user mode:

    # grep -E \"^set\\ssuperusers|^password_pbkdf2\" /boot/grub2/grub.cfg

    Example output:

    set superusers=\"root\"
    password_pbkdf2 root grub.pbkdf2.sha512.[password_hash]

    If superusers is not set, this is a finding.
    If a password is not set for the super user, this is a finding.
  "
  desc 'fix', "
    Before proceeding, ensure a snapshot is taken to rollback if needed.

    At the command line, run the following command to generate a grub password:

    # grub2-mkpasswd-pbkdf2

    Enter a secure password and ensure this password is stored for break-glass situations. Users will not be able to recover the root account without knowing this separate password. Copy the resulting encrypted string.

    An example string is below:

    grub.pbkdf2.sha512.10000.983A13DF3C51BB2B5130F0B86DDBF0DEA1AAF766BD1F16B7840F79CE3E35494C4B99F505C99C150071E563DF1D7FE1F45456D5960C4C79DAB6C49298B02A5558.5B2C49E12D43CC5A876F6738462DE4EFC24939D4BE486CDB72CFBCD87FDE93FBAFCB817E01B90F23E53C2502C3230502BC3113BE4F80B0AFC0EE956E735F7F86

    Note: The grub2 package must be installed to generate a password for grub.

    Navigate to and open:

    /boot/grub2/grub.cfg

    Find the line that begins with \"set rootpartition\". Below this line, paste the following on its own line:

    set superusers=\"root\"

    Note: The superusers name can be a value other than root and is not tied to an OS account.

    Below this paste the following, substituting the user's own encrypted string from the steps above:

    password_pbkdf2 root <YOUR-LONG-STRING-FROM-ABOVE>

    Next edit the default Photon menuentry block with the \"--unrestricted\" parameter so that it will continue to boot without prompting for credentials, for example:

    menuentry \"Photon\" --unrestricted {
        linux /boot/$photon_linux root=$rootpartition $photon_cmdline $systemd_cmdline audit=1
        if [ -f /boot/$photon_initrd ]; then
            initrd /boot/$photon_initrd
        fi
    }

    When booting now, if users press \"e\" when the Photon splash screen appears, users will be prompted for credentials before being presented the option to edit the boot loader before system startup.

    Note: Photon does not support building grub changes via grub2-mkconfig.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-PHTN-50-000046'
  tag rid: 'SV-PHTN-50-000046'
  tag stig_id: 'PHTN-50-000046'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe file('/boot/grub2/grub.cfg') do
    its('content') { should match /^set\ssuperusers=.*$/ }
    its('content') { should match /^password_pbkdf2\sroot\sgrub.pbkdf2.sha512/ }
  end
end
