control 'UBTU-22-653035' do
  title "Ubuntu 22.04 LTS must allocate audit record storage capacity to store at least one weeks' worth of audit records, when audit records are not immediately sent to a central audit record storage facility."
  desc 'To ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems must be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS allocates audit record storage capacity to store at least one week's worth of audit records when audit records are not immediately sent to a central audit record storage facility.

Determine which partition the audit records are being written to by using the following command:

     $ sudo grep -i log_file /etc/audit/auditd.conf
     log_file = /var/log/audit/audit.log

Check the size of the partition that audit records are written to (with the example being "/var/log/audit/") by using the following command:

     $ sudo df -h /var/log/audit/
     /dev/sda2 24G 10.4G 13.6G 43% /var/log/audit

If the audit records are not written to a partition made specifically for audit records ("/var/log/audit" as a separate partition), determine the amount of space being used by other files in the partition by using the following command:

     $ sudo du -sh <audit_partition>
     1.8G /var/log/audit

Note: The partition size needed to capture a week's worth of audit records is based on the activity level of the system and the total storage capacity available.

If the audit record partition is not allocated for sufficient storage capacity, this is a finding.)
  desc 'fix', %q(Allocate enough storage capacity for at least one week's worth of audit records when audit records are not immediately sent to a central audit record storage facility.

If audit records are stored on a partition made specifically for audit records, use the "parted" program to resize the partition with sufficient space to contain one week's worth of audit records.

If audit records are not stored on a partition made specifically for audit records, a new partition with sufficient amount of space will need be to be created.

Set the auditd server to point to the mount point where the audit records must be located:

     $ sudo sed -i -E 's@^(log_file\s*=\s*).*@\1 <audit_partition_mountpoint>/audit.log@' /etc/audit/auditd.conf

where <audit_partition_mountpoint> is the aforementioned mount point.)
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64324r953596_chk'
  tag severity: 'low'
  tag gid: 'V-260595'
  tag rid: 'SV-260595r958752_rule'
  tag stig_id: 'UBTU-22-653035'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-64232r953597_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  log_file = auditd_conf.log_file
  minimum_accepted_partition_size = input('minimum_accepted_partition_size')

  log_file_dir = File.dirname(log_file)
  available_storage = filesystem(log_file_dir).size_kb
  describe("Audit record partition size should be more than the defined standard of #{minimum_accepted_partition_size}") do
    subject { available_storage.to_i }
    it { should be > minimum_accepted_partition_size }
  end
end
