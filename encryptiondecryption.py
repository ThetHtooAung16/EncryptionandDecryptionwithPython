from secrets import token_bytes
class EncryptAndDecrypt:

    def SecretKey(self,length):
        tb : bytes=token_bytes(length)
        SecretKey : int =int.from_bytes(tb,'big')
        return SecretKey

    def encrypt(self,orData):
        originalBytes : bytes = orData.encode()
        SecretKey : int =self.SecretKey(len(originalBytes))
        print("Secret Key:",SecretKey)

        raw_data : int = int.from_bytes(originalBytes,'big')

        Cypher_text : int =SecretKey ^ raw_data
        print("Cypher Text:",Cypher_text)
        return Cypher_text , SecretKey

    def decrypt(self,Cypher_text,SecretKey):
        raw_data : int = Cypher_text ^ SecretKey
        byte_data : bytes = raw_data.to_bytes((raw_data.bit_length()+5)//8,'big')
        decrypted_data= byte_data.decode()
        return decrypted_data



if __name__=="__main__":
    originalData=input("Input Data to encrypt:")
    end : EncryptAndDecrypt = EncryptAndDecrypt()
    Cypher_text , SecretKey = end.encrypt(originalData)
    decrypted_data=end.decrypt(Cypher_text,SecretKey)
    print("Original Data: ",decrypted_data)
