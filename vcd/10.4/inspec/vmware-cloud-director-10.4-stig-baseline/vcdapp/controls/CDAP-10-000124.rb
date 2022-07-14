control 'CDAP-10-000124' do
  title 'VMware Cloud Director must enable FIPs mode. '
  desc  'Encryption is only as good as the encryption modules utilized.  Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms'
  desc  'rationale', ''
  desc  'check', "
    FIPs mode enablement can be viewed by logging into the VCD appliance management interface at https://<fqdn or ip of vcd appliance>:5480.

    Select System Configuration.

    If any node listed has \"Appliance FIPS\" or \"Cell FIPS\" not set to On, this is a finding.
  "
  desc 'fix', "
    To configure the appliance to run in FIPS-compliant mode, you must manage both the appliance FIPS mode and the cell FIPS mode.

    To enable the FIPS mode on cells do the following:

    Login to the VCD provider admin portal and select Administration >> Settings >> SSL.

    Click Enable and check the box to indicate you understand the warnings and have verified them and want to proceed and then click Enable.

    Note: When the configuration finishes, VMware Cloud Director displays an Enable in Progress (Awaiting cells restart) message, and you can continue to the next step. When you enable or disable FIPS mode from the appliance management UI, the VMware Cloud Director appliance automatically restarts the cells.

    To enable the appliance to run in FIPS mode do the following for each appliance:

    Login to the VCD appliance management interface and select System Configuration.

    Under actions click Enable for the node you are logged into and click OK.

    Note: Appliance FIPS mode is the mode of the underlying appliance OS, embedded database, and various system libraries.
    Note: Cell FIPS mode is the mode of the VMware Cloud Director cell running on each appliance.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000416-AS-000140'
  tag satisfies: ['SRG-APP-000439-AS-000274', 'SRG-APP-000224-AS-000152', 'SRG-APP-000179-AS-000129']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CDAP-10-000124'
  tag cci: ['CCI-002450', 'CCI-002418', 'CCI-001188', 'CCI-000803']
  tag nist: ['SC-13', 'SC-8', 'SC-23 (3)', 'IA-7']

  result = http("https://#{input('vcdURL')}:5480/api/1.0.0/fips",
              method: 'GET',
              headers: {
                'Authorization' => "#{input('applianceBearerToken')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    cells = JSON.parse(result.body)
    cells.each do |cell|
      describe cell do
        its(['applianceFips']) { should cmp 'ON' }
        its(['cellFips']) { should cmp 'ON' }
      end
    end
  end
end
