control 'VLMA-8X-000008' do
  title 'VMware Aria Suite Lifecycle must use an SSL ceritifcate issued by a DoD certificate authority.'
  desc  'The use of a DoD certificate on the VMware Aria Suite Lifecycle appliance assures clients that the service they are connecting to is legitimate and trusted.'
  desc  'rationale', ''
  desc  'check', "
    Login to VMware Aria Suite Lifecycle as the admin@local account.

    Select \"Lifecycle Operations\" >> Settings >> Change Certificate to view the configuration.

    If the certificate specified for VMware Aria Suite Lifecycle is not issued from a trusted internal or DoD certificate authority, this is a finding.
  "
  desc 'fix', "
    Login to VMware Aria Suite Lifecycle as the admin@local account.

    A replacement certificate must first be imported into the locker.

    The requirements for PEM file are:
    Both certificate chain and key must be in the same file.
    The PEM file that are imported can have 2048 bits key or 4096 bits key.
    If the PEM file certificate is encrypted then the passphrase must be provided while importing the certificate into VMware Aria Suite Lifecycle.

    Select Locker >> Certificates >> Import.

    Import the new certificate by providing a name, pass phrase if required, and certificate file then click Import.

    Note - When you upload a PEM file, the private key and certificate chain details are populated automatically.

    To replace the VMware Aria Suite Lifecycle certificate:

    Select \"Lifecycle Operations\" >> Settings >> Change Certificate >> Replace Certificate.

    Select the certificate imported into the locker in the previous step and click next to run the Precheck and then Finish to replace the certificate.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag gid: 'V-VLMA-8X-000008'
  tag rid: 'SV-VLMA-8X-000008'
  tag stig_id: 'VLMA-8X-000008'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
