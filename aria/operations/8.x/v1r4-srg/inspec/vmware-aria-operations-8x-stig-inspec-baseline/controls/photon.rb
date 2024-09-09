include_controls 'photon' do
  # Sudo users
  skip_control 'PHTN-50-000133'

  # AIDE will be implemented in a later release
  skip_control 'PHTN-50-000127'
  skip_control 'PHTN-50-000237'
end
