control 'UBTU-22-271030' do
  title 'Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify Ubuntu 22.04 LTS is not configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface by using the following command:

Note: If no graphical user interface is installed, this requirement is not applicable.

     $ gsettings get org.gnome.settings-daemon.plugins.media-keys logout
     @as []

If the "logout" key is bound to an action, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to disable the Ctrl-Alt-Delete sequence when using a graphical user interface.

Create or edit a file named /etc/dconf/db/local.d/00-mediakeys with the following contents:

[org/gnome/settings-daemon/plugins/media-keys]
logout=@as []

Update the dconf settings:

$ sudo dconf update'
  impact 0.7
  tag check_id: 'C-64268r953428_chk'
  tag severity: 'high'
  tag gid: 'V-260539'
  tag rid: 'SV-260539r1184066_rule'
  tag stig_id: 'UBTU-22-271030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-64176r1184065_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  xorg_status = command('which Xorg').exit_status
  if xorg_status == 0
    describe command('grep -rF "logout=@as []" /etc/dconf/db/local.d/') do
      its('exit_status') { should eq 0 }
      its('stdout.strip') { should_not eq '' }
    end
  else
    impact 0.0
    describe command('which Xorg').exit_status do
      skip("GUI not installed.\nwhich Xorg exit_status: #{command('which Xorg').exit_status}")
    end
  end
end
