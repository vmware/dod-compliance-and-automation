class PowerCLICommand < Inspec.resource(1)
  name 'powercli_command'
  supports platform: 'vmware'
  desc 'Run PowerCLI commands via InSpec'
  example <<~EOX
    # Any output indicates TSM-SSH is enabled
    cmd = 'Get-VMhost | Get-VMHostService | Where {$_.Key -eq "TSM-SSH" -and $_.Running -eq $False}'

    describe powercli_command(cmd) do
      its('exit_status') { should cmp 0 }
      its('stdout') { should_not cmp '' }
    end
  EOX

  attr_reader :command

  def initialize(command = nil)
    if command == nil
      raise Inspec::Exceptions::ResourceFailed,
            'This resource requires a command as an argument'
    end

    @command = command
  end

  def result
    @result ||= inspec.backend.run_command(command)
  end

  def stdout
    result.stdout
  end

  def stderr
    result.stderr
  end

  def exit_status
    result.exit_status.to_i
  end

  def to_s
    "PowerCLI Command: #{@command}"
  end
end
