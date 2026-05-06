control 'UBTU-24-200042' do
  title 'Ubuntu 24.04 LTS must prevent a user from overriding the disabling of the graphical user smart card removal action.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, Ubuntu 24.04 LTS must provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.

'
  desc 'check', 'Note: This requirement assumes the use of the Ubuntu 24.04 LTS default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify Ubuntu 24.04 LTS disables the ability of the user to override the smart card removal action setting.

$ gsettings writable org.gnome.settings-daemon.peripherals.smartcard removal-action

false

If "removal-action" is writable and the result is "true", this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to prevent a user from overriding the disabling of the graphical user smart card removal action.

Add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock":

/org/gnome/settings-daemon/peripherals/smartcard/removal-action

Update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-78974r1107298_chk'
  tag severity: 'medium'
  tag gid: 'V-274873'
  tag rid: 'SV-274873r1107300_rule'
  tag stig_id: 'UBTU-24-200042'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-78879r1107299_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000057', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a', 'AC-11 a']

  xorg_status = command('which Xorg').exit_status
  if xorg_status == 0
    describe command('gsettings writable org.gnome.settings-daemon.peripherals.smartcard removal-action') do
      its('stdout') { should cmp 'false' }
    end
  else
    impact 0.0
    describe command('which Xorg').exit_status do
      skip("GUI not installed.\nwhich Xorg exit_status: #{command('which Xorg').exit_status}")
    end
  end
end
