# encoding: UTF-8

control 'V-219211' do
  title "The Ubuntu Operating system must disable the x86 Ctrl-Alt-Delete key
sequence if a graphical user interface is installed."
  desc  "A locally logged-on user who presses Ctrl-Alt-Delete, when at the
console, can reboot the system. If accidentally pressed, as could happen in the
case of a mixed OS environment, this can create the risk of short-term loss of
availability of systems due to unintentional reboot. In the graphical
environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is
reduced because the user will be prompted before any action is taken."
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system is not configured to reboot the system
when Ctrl-Alt-Delete is pressed when using a graphical user interface.

    Check that the \"logout\" target is not bound to an action with the
following command:

    # grep logout /etc/dconf/db/local.d/*

    logout=''

    If the \"logout\" key is bound to an action, is commented out, or is
missing, this is a finding.
  "
  desc  'fix', "
    Configure the system to disable the Ctrl-Alt-Delete sequence when using a
graphical user interface by creating or editing the
/etc/dconf/db/local.d/00-disable-CAD file.

    Add the setting to disable the Ctrl-Alt-Delete sequence for the graphical
user interface:

    [org/gnome/settings-daemon/plugins/media-keys]
    logout=''

    Then update the dconf settings:

    # dconf update
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-219211'
  tag rid: 'SV-219211r508662_rule'
  tag stig_id: 'UBTU-18-010150'
  tag fix_id: 'F-20935r304962_fix'
  tag cci: ['V-100649', 'SV-109753', 'CCI-000366']
  tag nist: ['CM-6 b']

  gnome_installed = (package('ubuntu-gnome-desktop').installed? || package('ubuntu-desktop').installed? || package('gdm3').installed?)
  if !gnome_installed
    describe "The GUI is installed on the system" do
      subject { gnome_installed }
      it { should be false }
    end
  else
    describe command("grep -R logout='' /etc/dconf/db/local.d/").stdout.strip.split("\n").entries do
      its('count') { should_not eq 0 }
    end
  end
end

