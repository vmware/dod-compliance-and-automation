control 'V-219346' do
  title 'Wireless network adapters must be disabled.'
  desc  "Without protection of communications with wireless peripherals,
confidentiality and integrity may be compromised because unprotected
communications can be intercepted and either read, altered, or used to
compromise the Ubuntu operating system.

    This requirement applies to wireless peripheral technologies (e.g.,
    wireless mice, keyboards, displays, etc.) used with an Ubuntu operating system.
    Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing
    Devices and Near Field Communications [NFC]) present a unique challenge by
    creating an open, unsecured port on a computer. Wireless peripherals must meet
    DoD requirements for wireless data transmission and be approved for use by the
    AO. Even though some wireless peripherals, such as mice and pointing devices,
    do not ordinarily carry information that need to be protected, modification of
    communications with these wireless peripherals may be used to compromise the
    Ubuntu operating system. Communication paths outside the physical protection of
    a controlled boundary are exposed to the possibility of interception and
    modification.

    Protecting the confidentiality and integrity of communications with
    wireless peripherals can be accomplished by physical means (e.g., employing
    physical barriers to wireless radio frequencies) or by logical means (e.g.,
    employing cryptographic techniques). If physical means of protection are
    employed, then logical means (cryptography) do not have to be employed, and
    vice versa. If the wireless peripheral is only passing telemetry data,
    encryption of the data may not be required.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000481-GPOS-000481"
  tag "satisfies": nil
  tag "gid": 'V-219346'
  tag "rid": "SV-219346r381511_rule"
  tag "stig_id": "UBTU-18-010521"
  tag "fix_id": "F-21070r305367_fix"
  tag "cci": [ "CCI-002418" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify that there are no wireless interfaces configured on the system.

    Check that the system does not have active wireless interfaces with the following command:

    Note: This requirement is Not Applicable for systems that do not have physical
    wireless network radios.

    # ifconfig -a | more

    eth0 Link encap:Ethernet HWaddr ff:ff:ff:ff:ff:ff
    inet addr:192.168.2.100 Bcast:192.168.2.255 Mask:255.255.255.0
    ...

    eth1 IEEE 802.11b ESSID:\"tacnet\"
    Mode:Managed Frequency:2.412 GHz Access Point: 00:40:E7:22:45:CD
    ...

    lo Link encap:Local Loopback
    inet addr:127.0.0.1 Mask:255.0.0.0
    inet6 addr: ::1/128 Scope:Host
    ...

    If a wireless interface is configured and has not been documented and approved by the Information
    System Security Officer (ISSO), this is a finding.
  "
  desc 'fix', "Configure the system to disable all wireless network interfaces with the following command:

    # sudo ifdown [ADAPTER_NAME]
  "
  allowed_network_interfaces = input('allowed_network_interfaces')
  ifconfig_output = command('ifconfig -s | cut -d " " -f 1').stdout.split("\n")
  system_network_interfaces = ifconfig_output.drop(1)

  other_network_interfaces = system_network_interfaces - allowed_network_interfaces

  if other_network_interfaces.count > 0
    other_network_interfaces.each do |net_int|
      describe ('Interface: ' + net_int + ' not permitted') do
        subject { net_int }
        it { should be_empty }
      end
    end
  else
    describe 'Number of wireless network interfaces found' do
      subject { other_network_interfaces }
      its('count') { should eq 0 }
    end
  end
end
