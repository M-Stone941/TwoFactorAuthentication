require 'sequel'
require 'mysql2'

DB = Sequel.connect('mysql2://root@localhost:3306/passwordmanager?password=WNw$V3hmiYB6Co')
### Do a sequel model thing??



class WebsiteLogin < Sequel::Model
end

unless DB.table_exists?(:users)
  DB.create_table :users do
    primary_key :UserID
    String :Username
    String :MasterPasswordHash
    String :Salt
    Integer :EncryptionAlgorithm # 0=AES, 1=Serpent, 2=Twofish, 3=RC6, 4=MARS

  end
end

class User < Sequel::Model
end
