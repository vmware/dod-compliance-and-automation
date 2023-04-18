control 'VCSA-80-000009' do
  title 'The vCenter Server must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access.'
  desc  'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt on the vCenter Server Appliance, run the following command:

    # /usr/lib/vmware-TlsReconfigurator/VcTlsReconfigurator/reconfigureVc scan

    If the output indicates versions of TLS other than 1.2 are enabled, this is a finding.
  "
  desc 'fix', "
    At the command prompt on the vCenter Server Appliance, run the following command:

    # /usr/lib/vmware-TlsReconfigurator/VcTlsReconfigurator/reconfigureVc update -p TLSv1.2

    vCenter services will be restarted as part of the reconfiguration. The operating system will not be restarted.

    The \"--no-restart\" flag can be added to restart services at a later time.

    Changes will not take effect until all services are restarted or the appliance is rebooted.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000014'
  tag satisfies: ['SRG-APP-000156', 'SRG-APP-000157', 'SRG-APP-000219', 'SRG-APP-000439', 'SRG-APP-000440', 'SRG-APP-000441', 'SRG-APP-000442', 'SRG-APP-000560', 'SRG-APP-000565', 'SRG-APP-000625', 'SRG-APP-000645']
  tag gid: 'V-VCSA-80-000009'
  tag rid: 'SV-VCSA-80-000009'
  tag stig_id: 'VCSA-80-000009'
  tag cci: ['CCI-000068', 'CCI-000382', 'CCI-001184', 'CCI-001453', 'CCI-001941', 'CCI-001942', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'CM-7 b', 'IA-2 (8)', 'IA-2 (9)', 'SC-13', 'SC-23', 'SC-8', 'SC-8 (1)', 'SC-8 (2)']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
