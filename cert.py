import ExtraUtils.asyncTokens as astk
config = {
    "self": {
        "key": "E:\Developement\RTS-Modules\RTS_RemoteTunnelService\self.key",
        "pem": "E:\Developement\RTS-Modules\RTS_RemoteTunnelService\self.pem"
    }
}

self_pem, self_key = astk.gen_keypair()
with open(config["self"]["key"], 'w') as file:
    file.write(astk.serial(self_key))
with open(config["self"]["pem"], 'w') as file:
    file.write(astk.serial(self_pem))

#from ExtraTypes.snowflake import snowflake
#
#snow = snowflake().generate_id()
#print(snow)