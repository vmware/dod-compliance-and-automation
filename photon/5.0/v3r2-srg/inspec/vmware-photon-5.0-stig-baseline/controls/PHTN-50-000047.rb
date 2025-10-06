control 'PHTN-50-000047' do
  title 'The Photon operating system must disable unnecessary kernel modules.'
  desc  "
    It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

    Examples of nonessential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the following kernel modules are not loaded:

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
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag satisfies: ['SRG-OS-000114-GPOS-00059']
  tag gid: 'V-PHTN-50-000047'
  tag rid: 'SV-PHTN-50-000047'
  tag stig_id: 'PHTN-50-000047'
  tag cci: ['CCI-000381', 'CCI-000778']
  tag nist: ['CM-7 a', 'IA-3']

  disabled_modules = input('disabled_modules')
  disabled_modules.each do |mod|
    describe kernel_module(mod) do
      it { should be_disabled }
      it { should_not be_loaded }
    end
  end
end
