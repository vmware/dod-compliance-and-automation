control 'UBTU-24-200041' do
  title 'Ubuntu 24.04 LTS must prevent a user from overriding the disabling of the graphical user interface autorun function.'
  desc 'Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.

'
  desc 'check', 'Note: This requirement assumes the use of the Ubuntu 24.04 LTS default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify Ubuntu 24.04 LTS disables ability of the user to override the graphical user interface autorun setting.

Determine which profile the system database is using with the following command:

$ gsettings writable org.gnome.desktop.media-handling autorun-never

false

If "autorun-never" is writable, the result is "true". If this is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the Ubuntu 24.04 LTS GNOME desktop to not allow a user to change the setting that disables autorun on removable media.

Add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock" to prevent user modification:

/org/gnome/desktop/media-handling/autorun-never

Update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-78973r1101778_chk'
  tag severity: 'medium'
  tag gid: 'V-274872'
  tag rid: 'SV-274872r1107297_rule'
  tag stig_id: 'UBTU-24-200041'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-78878r1107296_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000778', 'CCI-001958']
  tag nist: ['IA-3', 'IA-3']

  xorg_status = command('which Xorg').exit_status
  if xorg_status == 0
    describe command('gsettings writable org.gnome.desktop.media-handling autorun-never') do
      its('stdout') { should cmp 'false' }
    end
  else
    impact 0.0
    describe command('which Xorg').exit_status do
      skip("GUI not installed.\nwhich Xorg exit_status: #{command('which Xorg').exit_status}")
    end
  end
end
