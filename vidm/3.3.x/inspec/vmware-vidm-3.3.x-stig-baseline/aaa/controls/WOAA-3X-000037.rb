control 'WOAA-3X-000037' do
  title 'Workspace ONE Access must be configured to encrypt locally stored credentials using a FIPS-validated cryptographic module.'
  desc  "
    Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

    AAA Services must enforce cryptographic representations of passwords when storing passwords in databases, configuration files, and log files. Passwords must be protected at all times; using a strong one-way hashing encryption algorithm with a salt is the standard method for providing a means to validate a password without having to store the actual password.

    Performance and time required to access are factors that must be considered, and the one-way hash is the most feasible means of securing the password and providing an acceptable measure of password security. If passwords are stored in clear text, they can be plainly read and easily compromised.
  "
  desc  'rationale', ''
  desc  'check', "
    Log into the Workspace ONE Access admin Console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click on the 'Dashboard' Tab.

    From the drop down select \"System Diagnostics Dashboard\".

    Search for \"FIPS Mode\" to view status of the deployment.

    If FIPS Mode is not enabled, this is a finding.

    Note: FIPs Mode is only supported in Workspace ONE Access 3.3.5+.
  "
  desc 'fix', "
    FIPs Mode cannot be enabled post-deployment and must be enabled at deployment.

    To install VMware Identity Manager in FIPS mode whether from vRSLCM or stand alone select the enable FIPS Mode option at time of deployment.

    Note: You cannot enable FIPS mode later if FIPS mode is disabled at the time of installation.

    Note: You cannot disable FIPS mode after you enable FIPS mode during the VMware Identity Manager installation.

    Note: Installing VMware Identity Manager Connector automatically activates FIPS mode. Use VMware Identity Manager Connector 3.3.5. If you deploy an older connector version, an error occurs.

    Note: For Active Directory over Integrated Windows Authentication (IWA), the minimum password length requirement for Active Directory users is 14 characters. The best practice is to implement the 14-character minimum before you install VMware Identity Manager in FIPS mode.

    Note: Enabling the Change Password feature for Active Directory users requires a minimum password length of 14 characters.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000171-AAA-000510'
  tag gid: 'V-WOAA-3X-000037'
  tag rid: 'SV-WOAA-3X-000037'
  tag stig_id: 'WOAA-3X-000037'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
  tag mitigations: "Shubham,\n\nTo check encryption algo used to encrypt locally stored passwords is picked from BC-FJA-1.0.2? or OpenSSL?\n\nBased on the answer, we can change this to AC and provide settings to check FIPS mode flag which can be enabled/ disabled.\n\nMW: Shubham confirmed it's BC-FJA-1.0.2"

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
