# encoding: utf-8
# copyright: 2018, ViolentOr
# author: ViolentOr


class MsSqlConfig < Inspec.resource(1)
  name 'mssql_config'
  desc 'Use the InSpec resource to get configuration of a DB'

  example "
    describe mssql_config(db_name: 'test_base', property_name: 'remote access') do
      its('value_configured') { should cmp 0 }
      its('value_in_use') { should cmp 0 }
    end

    describe mssql_config do
      its('db_count') { should_not cmp 0 }
      its('db_list') { should include 'DBA' }
    end

    describe mssql_config do
      its('db_count') { should_not cmp 0 }
      its('db_list') { should include 'DBA' }
    end
  "

    def initialize(opts = {})
    @db_name = opts[:db_name]
    @property_name = opts[:property_name]
    @property_type = opts[:property_type] || 'configuration'
    @user = opts[:user]
    @password = opts[:password]
    @host = opts[:host]
    @instance = opts[:instance]
    connection_string = String.new
    connection_string += "user: '#{@user}', pass: ''#{@password}'" unless @user.nil? || @password.nil?
    connection_string += "host: '#{@host}'" unless @host.nil?
    connection_string += "host: '#{@instance}'" unless @instance.nil?

    if connection_string.eql?(String.new)
      @connection = inspec.mssql_session
    else
      @connection = inspec.mssql_session(connection_string)
    end

    if @connection.query('select getdate()').empty?
      skip_resource "Can't connect to SQL Server \"#{@host}\\#{@instance}\""
      return @params = []
    end

    @db_list = 'This attribute is availible only if DB is not specified'
    @db_count = 'This attribute is availible only if DB is not specified'
    @value_configured = 'This attribute is used only in "property_type: \'configuration\' request'
    @value_in_use = 'This attribute is used only in "property_type: \'configuration\' request'
    @trustworthy = 'This attribute is used only in "property_type: \'trustworthy\' request'
    @unsafe_assemblies_amount = 'This attribute is used only in "property_type: \'assembly\' request'
    @sa = 'This attribute is used only in "property_type: \'sa\' request'
    @guest_connect_permissions = 'This attribute is used only in "property_type: \'guest_connect\' request'
    @desc_string = 'MS SQL Configuration'
    @policy_list = 'This attribute is used only in "property_type: \'sql_logins\' request'
    @expiration_list = 'This attribute is used only in "property_type: \'sql_logins\' request'
    case @property_type.upcase
    when 'configuration'.upcase
      if !(@property_name.nil? || @db_name.nil?)
        begin
          @value_in_use = Integer(@connection.query("SELECT CAST(value_in_use as int) as value FROM [#{@db_name}].sys.configurations WHERE name = '#{@property_name}'").row(0).column('value').value)
          @value_configured = Integer(@connection.query("SELECT CAST(value as int) as value FROM [#{@db_name}].sys.configurations WHERE name = '#{@property_name}'").row(0).column('value').value)
        rescue CSV::MalformedCSVError => e
          @value_in_use = "DB #{@db_name} not accessible"
          @value_configured = "DB #{@db_name} not accessible"
        end    
      else
        string = String.new
        string += 'property_name ' unless !@property_name.nil?
        string =+ 'and ' unless !(@property_name.nil? && @db_name.nil?)
        string += 'db_name ' unless !@db_name.nil?
        string += 'was not defined'
        @value_in_use = string
        @value_configured = string
        @db_list = getDbList
        @db_count = @db_list.size
      end
      @desc_string = String.new
      @desc_string += 'MS SQL Configuration'
      @desc_string += " for DB #{@db_name}" unless @db_name.nil?
      @desc_string += " of '#{@property_name}' setting" unless @property_name.nil?
      @desc_string += " on server #{@host}\\#{@instance}" unless @instance.nil? || @host.nil?
      @desc_string += " checked under #{@user}" unless @user.nil?
    when 'trustworthy'.upcase
      begin
        result =  @connection.query("select name from [#{@db_name}].sys.databases where is_trustworthy_on = 1")
        i = 0
        @trustworthy = Array.new
        result.size.times do
          @trustworthy += Array(result.row(i).column('name').value.to_s)
          i+=1
        end
      rescue CSV::MalformedCSVError => e
        @trustworthy = "DB #{@db_name} not accessible"
      end
      @desc_string = String.new
      @desc_string += 'List of trustworthy DBs'
      @desc_string += " for DB #{@db_name}" unless @db_name.nil?
      @desc_string += " on server #{@host}\\#{@instance}" unless @instance.nil? || @host.nil?
      @desc_string += " checked under #{@user}" unless @user.nil?
    when 'assembly'.upcase
      begin
        @unsafe_assemblies_amount = Integer(@connection.query("SELECT count(1) as value FROM [#{@db_name}].sys.assemblies where is_user_defined = 1 and permission_set_desc != 'SAFE_ACCESS'").row(0).column('value').value)          
      rescue CSV::MalformedCSVError => e
        @unsafe_assemblies_amount = "DB #{@db_name} not accessible"
      end
      @desc_string = String.new
      @desc_string += 'Amount of user defined assemblies with with non-SAFE_ACCESS permissions'
      @desc_string += " for DB #{@db_name}" unless @db_name.nil?
      @desc_string += " on server #{@host}\\#{@instance}" unless @instance.nil? || @host.nil?
      @desc_string += " checked under #{@user}" unless @user.nil?
    when 'sa'.upcase
      begin
        @sa = @connection.query("select name, is_disabled from [#{@db_name}].sys.server_principals where sid = 0x01")
      rescue CSV::MalformedCSVError => e
        @sa = "DB #{@db_name} not accessible"
      end
      @desc_string = String.new
      @desc_string += 'SA User'
      @desc_string += " for DB #{@db_name}" unless @db_name.nil?
      @desc_string += " on server #{@host}\\#{@instance}" unless @instance.nil? || @host.nil?
      @desc_string += " checked under #{@user}" unless @user.nil?
    when 'guest_connect'.upcase
      begin
        @guest_connect_permissions = Integer(@connection.query("SELECT count(1) as amount FROM [#{@db_name}].sys.database_permissions WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID('guest') AND [state_desc] LIKE 'GRANT%' AND [permission_name] = 'CONNECT'").row(0).column('amount').value)
      rescue CSV::MalformedCSVError => e
        @guest_connect_permissions = "DB #{@db_name} not accessible"
      end
      @desc_string = String.new
      @desc_string += "DB #{@db_name}" unless @db_name.nil?
      @desc_string += " of '#{@property_name}' setting" unless @property_name.nil?
      @desc_string += " on server #{@host}\\#{@instance}" unless @instance.nil? || @host.nil?
      @desc_string += " checked under #{@user}" unless @user.nil?
    when 'SERVERPROPERTY'.upcase
      if !(@property_name.nil?)
        begin
          @value_in_use = Integer(@connection.query("SELECT SERVERPROPERTY('#{@property_name}') as [mode]").row(0).column('mode').value)
        rescue CSV::MalformedCSVError => e
          @value_in_use = "DB #{@db_name} not accessible"
        end
        @value_configured = @value_in_use
        @desc_string = String.new
        @desc_string += "Server property #{@property_name}"
        @desc_string += " on server #{@host}\\#{@instance}" unless @instance.nil? || @host.nil?
        @desc_string += " checked under #{@user}" unless @user.nil?
      else
        string = String.new
        string += 'property_name ' unless !@property_name.nil?
        string =+ 'and ' unless !(@property_name.nil? && @db_name.nil?)
        string += 'db_name ' unless !@db_name.nil?
        string += 'was not defined'
        @value_in_use = string
        @value_configured = string
      end
    when 'sql_logins'.upcase
      if !(@db_name.nil?)
        failed_policy = false
        failed_expiration = false
        policy = nil
        expiration = nil
        begin
          policy = @connection.query("SELECT name FROM [#{@db_name}].sys.sql_logins where is_policy_checked = 0")
        rescue CSV::MalformedCSVError => e
          failed_policy = true
          @policy_list = "DB #{@db_name} not accessible"
        end
        begin
          expiration = @connection.query("SELECT name FROM [#{@db_name}].sys.sql_logins where is_expiration_checked = 0")
        rescue CSV::MalformedCSVError => e
          failed_expiration = true
          @expiration_list = "DB #{@db_name} not accessible"
        end
        if !(failed_policy)
          i = 0
          @policy_list = Array.new
          policy.size.times do
            @policy_list += Array(policy.row(i).column('name').value.to_s)
            i+=1
          end
        end
        if !(failed_expiration)
          i = 0
          @expiration_list = Array.new
          expiration.size.times do
            @expiration_list += Array(expiration.row(i).column('name').value.to_s)
            i+=1
          end
        end
        @desc_string = String.new
        @desc_string += "Account password policy"
        @desc_string += " for DB #{@db_name}" unless @db_name.nil?
        @desc_string += " on server #{@host}\\#{@instance}" unless @instance.nil? || @host.nil?
        @desc_string += " checked under #{@user}" unless @user.nil?
      else
        @value_in_use = 'db_name was not defined'
        @value_configured = @value_in_use
      end
    end
  end

  def disabled?
    if (!@sa.is_a?(String))
      return 1.eql?(Integer(@sa.row(0).column('is_disabled').value))
    end
    return @sa
  end

  def enabled?
    if (!@sa.is_a?(String))
      return !1.eql?(Integer(@sa.row(0).column('is_disabled').value))
    end
    return @sa
  end

  def renamed?
    if (!@sa.is_a?(String))
      return !'sa'.eql?(@sa.row(0).column('name').value.to_s)
    end
    return @sa
  end

  def connectable_by_guest?
    if (@guest_connect_permissions.is_a?(Integer))
      return !0.eql?(@guest_connect_permissions)
    end
    return @guest_connect_permissions
  end

  def value_in_use
    return @value_in_use
  end 

  def value_configured
    return @value_configured
  end

  def db_list
    return @db_list
  end

  def db_count
    return @db_count
  end

  def trustworthy_list
    return @trustworthy
  end

  def unsafe_assemblies_amount
    return @unsafe_assemblies_amount
  end

  def unpassword_policed_users
    return @policy_list
  end

  def unexpirable_users
    return @expiration_list
  end

  def to_s
    return @desc_string
  end

  private
  def getDbList
    databases = @connection.query('SELECT name FROM master.dbo.sysdatabases')
    i = 0
    list = Array.new
    databases.size.times do
      list += Array(databases.row(i).column('name').value.to_s)
      i+=1
    end
    return list
  end
end
