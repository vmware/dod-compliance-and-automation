control 'VCSA-70-000009' do
  title 'The vCenter Server must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access.'
  desc  'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt on the vCenter Server Appliance, execute the following command:

    # /usr/lib/vmware-TlsReconfigurator/VcTlsReconfigurator/reconfigureVc scan

    If the output indicates versions of TLS other than 1.2 are enabled, this is a finding.
  "
  desc 'fix', "
    At the command prompt on the vCenter Server Appliance, execute the following command(s):

    # /usr/lib/vmware-TlsReconfigurator/VcTlsReconfigurator/reconfigureVc backup

    # /usr/lib/vmware-TlsReconfigurator/VcTlsReconfigurator/reconfigureVc update -p TLS1.2

    vCenter services will be restarted as part of the reconfiguration, the OS will not be restarted.

    You can add the --no-restart flag to restart services at a later time.

    Changes will not take effect until all services are restarted or the appliance is rebooted.

    Note: This change should be performed on vCenter prior to ESXi.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000014'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000009'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
