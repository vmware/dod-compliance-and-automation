control 'VCSA-70-000294' do
  title 'vCenter Native Key Providers must be backed up with a strong password.'
  desc  'The vCenter Native Key Provider feature was introduced in U2 and acts as a key provider for encryption-based capabilities, such as encrypted virtual machines without requiring an external KMS solution. When enabling this feature, a backup must be taken that is a PKCS#12 formatted file. If no password is provided during the backup process, this presents the opportunity for this to be used maliciously and compromise the environment.'
  desc  'rationale', ''
  desc  'check', "
    If the vCenter Native Key Provider feature is not in use, this is not applicable.

    Interview the system administrator and determine if a password was provided for any backups taken of the Native Key Provider.

    If backups exist for the Native Key Provider that are not password protected, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Host and Clusters.

    Select a vCenter Server >> Configure >> Settings >> Key Providers.

    Select the Native Key Provider, click \"Back-up\", and check the box \"Protect Native Key Provider data with password\".

    Provide a strong password and click \"Back up key provider\".

    Delete any previous backups that were not protected with a password.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-256374'
  tag rid: 'SV-256374r885733_rule'
  tag stig_id: 'VCSA-70-000294'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
