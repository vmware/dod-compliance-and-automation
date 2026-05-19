control 'UBTU-24-600230' do
  title 'Ubuntu 24.04 LTS must disable all wireless network adapters.'
  desc 'Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise Ubuntu 24.04 LTS.

This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with an operating system. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DOD requirements for wireless data transmission and be approved for use by the approving authority (AO). Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise Ubuntu 24.04 LTS. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.'
  desc 'check', 'Note: This requirement is not applicable for systems that do not have physical wireless network radios.

Verify there are no wireless interfaces configured on the system with the following command:

$ ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename

If a wireless interface is configured and has not been documented and approved by the information system security officer (ISSO), this is a finding.'
  desc 'fix', 'List all the wireless interfaces with the following command:

$ ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename

For each interface, configure the system to disable wireless network interfaces with the following command:

$ sudo ifdown <interface name>

For each interface listed, find their respective module with the following command:

$ basename $(readlink -f /sys/class/net/<interface name>/device/driver)

where <interface name> must be substituted by the actual interface name.

Create a file in the "/etc/modprobe.d" directory and for each module, add the following line:

install <module name> /bin/true

For each module from the system, execute the following command to remove it:

$ sudo modprobe -r <module name>'
  impact 0.5
  tag check_id: 'C-74788r1066752_chk'
  tag severity: 'medium'
  tag gid: 'V-270755'
  tag rid: 'SV-270755r1066754_rule'
  tag stig_id: 'UBTU-24-600230'
  tag gtitle: 'SRG-OS-000481-GPOS-00481'
  tag fix_id: 'F-74689r1066753_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  approved_Wireless_network_interfaces = input('approved_wireless_network_interfaces')

  interfaces_cmd = command('ls -L -d /sys/class/net/*/wireless 2>/dev/null | xargs -r dirname | xargs -r basename')
  wireless_interfaces = interfaces_cmd.stdout.strip.split("\n")

  if wireless_interfaces.empty?
    impact 0.0
    describe 'Wireless interfaces check' do
      skip 'No wireless interfaces were detected on the system.'
    end
  else
    wireless_interfaces.each do |interface|
      describe "Wireless interface '#{interface}'" do
        it 'should be in the list of approved wireless network interfaces' do
          expect(approved_Wireless_network_interfaces).to include(interface)
        end
      end
    end
  end
end
