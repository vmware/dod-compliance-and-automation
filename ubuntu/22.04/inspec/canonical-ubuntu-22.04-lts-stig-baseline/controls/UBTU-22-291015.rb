control 'UBTU-22-291015' do
  title 'Ubuntu 22.04 LTS must disable all wireless network adapters.'
  desc 'Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise the operating system.

This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with an operating system. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DOD requirements for wireless data transmission and be approved for use by the AO. Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the operating system. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.'
  desc 'check', 'Verify that there are no wireless interfaces configured on the system by using the following command:

Note: If the system does not have any physical wireless network radios, this requirement is not applicable.

     $ cat /proc/net/wireless

If any wireless interface names are listed under "Interface" and have not been documented and approved by the information system security officer (ISSO), this is a finding.'
  desc 'fix', 'Disable all wireless network interfaces by using the following command:

     $ sudo ifdown <wireless_interface_name>

For each interface listed, find their respective module by using the following command:

     $ basename $(readlink -f /sys/class/net/<wireless_interface_name>/device/driver)

where <wireless_interface_name> must be substituted by the actual interface name.

Create and/or append a custom file under "/etc/modprobe.d/" by using the following command:

     $ sudo su -c "echo install <module_name> /bin/false >> /etc/modprobe.d/stig.conf"

where <module_name> must be substituted by the actual module name.

For each module from the system, execute the following command to remove it:

     $ sudo modprobe -r <module_name>'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64270r953434_chk'
  tag severity: 'medium'
  tag gid: 'V-260541'
  tag rid: 'SV-260541r958358_rule'
  tag stig_id: 'UBTU-22-291015'
  tag gtitle: 'SRG-OS-000481-GPOS-00481'
  tag fix_id: 'F-64178r953435_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  approved_Wireless_network_interfaces = input('approved_wireless_network_interfaces')
  wireless_interfaces = command("cat /proc/net/wireless | awk 'NR>2 {print $1}' | sed 's/://g'").stdout.split

  if wireless_interfaces.count > 0
    wireless_interfaces.each do |interface|
      describe "Wireleess Interface '#{interface}'" do
        it 'should be in the list of approved wireless network interfaces' do
          expect(approved_Wireless_network_interfaces).to include(interface)
        end
      end
    end
  else
    impact 0.0
    describe 'No Wireless Interface Exist' do
      skip "No wireless interface names are listed under 'Interface'"
    end
  end
end
