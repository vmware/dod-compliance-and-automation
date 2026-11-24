control 'UBTU-24-200040' do
  title 'Ubuntu 24.04 LTS must prevent a user from overriding the disabling of the graphical user interface automount function.'
  desc 'A nonprivileged account is any operating system account with authorizations of a nonprivileged user.

'
  desc 'check', %q(Note: This requirement assumes the use of the Ubuntu 24.04 LTS default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify Ubuntu 24.04 LTS disables the ability of the user to override the graphical user interface automount setting.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user

system-db:local

Check that the automount setting is locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ grep 'automount-open' /etc/dconf/db/local.d/locks/*

/org/gnome/desktop/media-handling/automount-open

If the command does not return at least the example result, this is a finding.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS so the GNOME desktop does not allow a user to change the setting that disables automated mounting of removable media.

Add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock" to prevent user modification:

/org/gnome/desktop/media-handling/automount-open

Update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-74712r1101775_chk'
  tag severity: 'medium'
  tag gid: 'V-270679'
  tag rid: 'SV-270679r1107295_rule'
  tag stig_id: 'UBTU-24-200040'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-74613r1107294_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']

  xorg_status = command('which Xorg').exit_status
  if xorg_status == 0
    describe 'Prevent a user from overriding the disabling of the graphical user interface automount function.' do
      skip 'GUI automount function checks must be preformed manually'
    end
  else
    impact 0.0
    describe command('which Xorg').exit_status do
      skip("GUI not installed.\nwhich Xorg exit_status: #{command('which Xorg').exit_status}")
    end
  end
end
