include_controls 'application'
include_controls 'nginx' do
  skip_control 'VLMN-8X-000026'
  skip_control 'VLMN-8X-000034'
end
include_controls 'photon'
include_controls 'vpostgres'
