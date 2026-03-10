control 'UBTU-22-271025' do
  title 'Ubuntu 22.04 LTS must initiate a graphical session lock after 15 minutes of inactivity.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, a session lock of Ubuntu 22.04 LTS must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.'
  desc 'check', 'Verify Ubuntu 22.04 LTS has a graphical user interface session lock configured to activate after 15 minutes of inactivity by using the following commands:

Note: If no graphical user interface is installed, this requirement is not applicable.

Get the following settings to verify the graphical user interface session is configured to lock the graphical user session after 15 minutes of inactivity:

     $ gsettings get org.gnome.desktop.screensaver lock-enabled
     true

     $ gsettings get org.gnome.desktop.screensaver lock-delay
     uint32 0

     $ gsettings get org.gnome.desktop.session idle-delay
     uint32 900

If "lock-enabled" is not set to "true", is commented out, or is missing, this is a finding.

If "lock-delay" is set to a value greater than "0", or if "idle-delay" is set to a value greater than "900", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to lock the current graphical user interface session after 15 minutes of inactivity.

Create or edit a file named /etc/dconf/db/local.d/00-screensaver with the following contents:

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=0

[org/gnome/desktop/session]
idle-delay=600'
  impact 0.5
  tag check_id: 'C-64267r953425_chk'
  tag severity: 'medium'
  tag gid: 'V-260538'
  tag rid: 'SV-260538r1069119_rule'
  tag stig_id: 'UBTU-22-271025'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-64175r1069118_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']

  xorg_status = command('which Xorg').exit_status
  if xorg_status == 0
    describe command('gsettings get org.gnome.desktop.screensaver lock-enabled') do
      its('stdout') { should cmp 'true' }
    end
    describe command("gsettings get org.gnome.desktop.screensaver lock-delay | awk '{print $2}'") do
      its('stdout') { should <= '0' }
    end
    describe command("gsettings get org.gnome.desktop.session idle-delay | awk '{print $2}'") do
      its('stdout') { should <= '900' }
    end
  else
    impact 0.0
    describe command('which Xorg').exit_status do
      skip("GUI not installed.\nwhich Xorg exit_status: #{command('which Xorg').exit_status}")
    end
  end
end
