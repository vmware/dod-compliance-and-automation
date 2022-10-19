control 'PHTN-30-000032' do
  title 'The Photon operating system must disable the loading of unnecessary kernel modules.'
  desc  'To support the requirements and principles of least functionality, the operating system must provide only essential capabilities and limit the use of modules, protocols, and/or services to only those required for the proper functioning of the product.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # modprobe --showconfig | grep \"^install\" | grep \"/bin\"

    Expected result:

    install sctp /bin/false
    install dccp /bin/false
    install dccp_ipv4 /bin/false
    install dccp_ipv6 /bin/false
    install ipx /bin/false
    install appletalk /bin/false
    install decnet /bin/false
    install rds /bin/false
    install tipc /bin/false
    install bluetooth /bin/false
    install usb_storage /bin/false
    install ieee1394 /bin/false
    install cramfs /bin/false
    install freevxfs /bin/false
    install jffs2 /bin/false
    install hfs /bin/false
    install hfsplus /bin/false
    install squashfs /bin/false
    install udf /bin/false

    The output may include other statements outside of the expected result.

    If the output does not include at least every statement in the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/modprobe.d/modprobe.conf

    Set the contents as follows:

    install sctp /bin/false
    install dccp /bin/false
    install dccp_ipv4 /bin/false
    install dccp_ipv6 /bin/false
    install ipx /bin/false
    install appletalk /bin/false
    install decnet /bin/false
    install rds /bin/false
    install tipc /bin/false
    install bluetooth /bin/false
    install usb_storage /bin/false
    install ieee1394 /bin/false
    install cramfs /bin/false
    install freevxfs /bin/false
    install jffs2 /bin/false
    install hfs /bin/false
    install hfsplus /bin/false
    install squashfs /bin/false
    install udf /bin/false
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag satisfies: []
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000032'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b', 'IA-3']

  disabled_modules = input('disabled_modules')

  disabled_modules.each do |mod|
    describe kernel_module(mod) do
      it { should be_disabled }
      it { should_not be_loaded }
    end
  end
end
