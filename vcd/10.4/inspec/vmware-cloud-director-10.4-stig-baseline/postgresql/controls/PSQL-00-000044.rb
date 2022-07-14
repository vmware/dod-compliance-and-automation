control 'PSQL-00-000044' do
  title 'PostgreSQL must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.'
  desc  "
    Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data.  Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

    Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

    The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.

    NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.
  "
  desc  'rationale', ''
  desc  'check', "
    As a system administrator, perform the following at the command prompt:

    # openssl version

    If \"fips\" is not included in the OpenSSL version, this is a finding.
  "
  desc 'fix', 'Install a version of OpenSSL that is FIPs validated.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag satisfies: ['SRG-APP-000514-DB-000381', 'SRG-APP-000514-DB-000382', 'SRG-APP-000514-DB-000383']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PSQL-00-000044'
  tag cci: ['CCI-000803', 'CCI-002450', 'CCI-002450', 'CCI-002450']
  tag nist: ['IA-7', 'SC-13', 'SC-13', 'SC-13']

  describe command('openssl version') do
    its('stdout.strip') { should match /fips/ }
  end
  describe command('openssl md5 /etc/issue') do
    its('stdout.strip') { should match /disabled for fips/ }
  end
end
