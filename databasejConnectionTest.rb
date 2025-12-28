require 'sequel'
require 'mysql2'

DB = Sequel.connect('mysql2://root@localhost:3306/passwordmanager?password=WNw$V3hmiYB6Co')

unless DB.table_exists?(:fruits)
  DB.create_table :fruits do
    primary_key :id

    column :name, String
    column :amount, Integer
  end
end
