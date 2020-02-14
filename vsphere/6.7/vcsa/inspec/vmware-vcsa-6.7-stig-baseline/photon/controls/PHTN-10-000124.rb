control "PHTN-10-000124" do
  title "The Photon operating system must enforce approved authorizations for
logical access to information and system resources in accordance with
applicable access control policies."
  desc  "If the system does not require authentication before it boots into
single-user mode, anyone with vCenter console rights to the VCSA can trivially
access all files on the system. GRUB2 is the boot loader for Photon OS and is
can be configured to require a password to boot into single-user mode or make
modifications to the boot menu.

    Note: The VCSA does not support building grub changes via grub2-mkconfig."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000080-GPOS-00048"
  tag gid: nil
  tag rid: "PHTN-10-000124"
  tag stig_id: "PHTN-10-000124"
  tag cci: "CCI-000213"
  tag nist: ["AC-3", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep -i ^password_pbkdf2 /boot/grub2/grub.cfg

If there is not output, this is a finding.

If the output does not begin with \"password_pbkdf2 root\", this is a finding."
  desc 'fix', "At the command line, execute the following command:

# grub2-mkpasswd-pbkdf2

Enter a secure password and ensure this password is stored for break-glass
situations. You will not be able to recover the vCenter root account without
knowing this separate password. Copy the resulting encrypted string. An example
string is below:

grub.pbkdf2.sha512.10000.983A13DF3C51BB2B5130F0B86DDBF0DEA1AAF766BD1F16B7840F79CE3E35494C4B99F505C99C150071E563DF1D7FE1F45456D5960C4C79DAB6C49298B02A5558.5B2C49E12D43CC5A876F6738462DE4EFC24939D4BE486CDB72CFBCD87FDE93FBAFCB817E01B90F23E53C2502C3230502BC3113BE4F80B0AFC0EE956E735F7F86

Open /boot/grub2/grub.cfg with a text editor. Find the line that begins with
\"set rootpartition\". Below this line, paste the following on its own line:

set superusers=\"root\"

Below this paste the following, substituting your own encrypted string from the
steps above:

password_pbkdf2 root <YOUR-LONG-STRING-FROM-ABOVE>

The VCSA ships with one menuentry block by default. Copy that entire block and
paste it right below itself.

Example:
menuentry \"Photon\" {
    linux \"/\"$photon_linux root=$rootpartition net.ifnames=0 $photon_cmdline
coredump_filter=0x37 consoleblank=0
    if [ \"$photon_initrd\" ]; then
        initrd \"/\"$photon_initrd
    fi
}
menuentry \"Photon\" {
    linux \"/\"$photon_linux root=$rootpartition net.ifnames=0 $photon_cmdline
coredump_filter=0x37 consoleblank=0
    if [ \"$photon_initrd\" ]; then
        initrd \"/\"$photon_initrd
    fi
}

Modify the first menuentry block to add the \"--unrestricted\" option as
follows:

menuentry \"Photon\" --unrestricted {

Modify the second menuentry block to add the allowed user as follows

menuentry \"Recover Photon\" --users root {

This concludes the fix. To verify, here is an example grub.cfg snippet.

...
set rootpartition=PARTUUID=326e5b0f-42fb-471a-8209-18964c4a2ed3
set superusers=\"root\"
password_pbkdf2 root
grub.pbkdf2.sha512.10000.983A13DF3C51BB2B5130F0B86DDBF0DEA1AAF766BD1F16B7840F79CE3E35494C4B99F505C99C150071E563DF1D7FE1F45456D5960C4C79DAB6C49298B02A5558.5B2C49E12D43CC5A876F6738462DE4EFC24939D4BE486CDB72CFBCD87FDE93FBAFCB817E01B90F23E53C2502C3230502BC3113BE4F80B0AFC0EE956E735F7F86

menuentry \"Photon\" --unrestricted {
    linux \"/\"$photon_linux root=$rootpartition net.ifnames=0 $photon_cmdline
coredump_filter=0x37 consoleblank=0
    if [ \"$photon_initrd\" ]; then
        initrd \"/\"$photon_initrd
    fi
}

menuentry \"Recover Photon\" --users root {
    linux \"/\"$photon_linux root=$rootpartition net.ifnames=0 $photon_cmdline
coredump_filter=0x37 consoleblank=0
    if [ \"$photon_initrd\" ]; then
        initrd \"/\"$photon_initrd
    fi
}"

  describe command('grep -i ^password_pbkdf2 /boot/grub2/grub.cfg') do
      its ('stdout.strip') { should match /.*password_pbkdf2 root.*/ }
  end

end

