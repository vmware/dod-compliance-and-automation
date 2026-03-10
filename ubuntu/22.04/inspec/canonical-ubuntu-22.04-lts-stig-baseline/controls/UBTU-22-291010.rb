control 'UBTU-22-291010' do
  title 'Ubuntu 22.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.'
  desc 'check', 'Verify Ubuntu 22.04 LTS disables ability to load the USB storage kernel module by using the following command:

     $ grep usb-storage /etc/modprobe.d/* | grep "/bin/false"
     /etc/modprobe.d/stig.conf:install usb-storage /bin/false

If the command does not return any output, or the line is commented out, this is a finding.

Verify Ubuntu 22.04 LTS disables the ability to use USB mass storage device.

     $ grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"
     /etc/modprobe.d/stig.conf:blacklist usb-storage

If the command does not return any output, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to disable using the USB storage kernel module.

Create and/or append a custom file under "/etc/modprobe.d/" to contain the following:

     $ sudo su -c "echo install usb-storage /bin/false >> /etc/modprobe.d/stig.conf"

Configure Ubuntu 22.04 LTS to disable the ability to use USB mass storage devices.

     $ sudo su -c "echo blacklist usb-storage >> /etc/modprobe.d/stig.conf"'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64269r953431_chk'
  tag severity: 'medium'
  tag gid: 'V-260540'
  tag rid: 'SV-260540r986276_rule'
  tag stig_id: 'UBTU-22-291010'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-64177r953432_fix'
  tag 'documentable'
  tag cci: ['CCI-001958', 'CCI-003959']
  tag nist: ['IA-3', 'CM-7 (9) (b)']

  describe kernel_module('usb-storage') do
    it { should be_disabled }
    it { should_not be_loaded }
    it { should be_blacklisted }
  end
end
