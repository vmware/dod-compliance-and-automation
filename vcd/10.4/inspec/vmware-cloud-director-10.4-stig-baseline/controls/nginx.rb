include_controls 'nginx' do
  # VCD shares a certificate and key between the management interface and PostgreSQL and cannot support changing permissions on the key file to support this requirement as it would break PostgreSQL.
  skip_control 'NGNX-WB-000040'
  # Currently VCD permissions for /etc/nginx are nginx:nginx and not root and will be addressed in a future version but cannot be changed atm.
  skip_control 'NGNX-WB-000078'
  # This is covered in a VCD App control
  skip_control 'NGNX-WB-000101'
end
