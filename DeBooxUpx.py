#!/usr/bin/env python3
try:
    from Cryptodome.Cipher import AES
except ModuleNotFoundError:
    from Crypto.Cipher import AES
    from Crypto import version_info
    if version_info[0] == 2:
        raise SystemExit('Need either `pycryptodome` or `pycryptodomex`,'\
                ' NOT `pycrypto`!')
import csv

class DeBooxUpx:
    blockSize: int = 2**12  # 4KiB

    def __init__(self,
                 KEY: str,
                 IV: str):
        self.key: bytes = bytes.fromhex(KEY)
        self.iv: bytes = bytes.fromhex(IV)
    def enUpxStream(self, inputFile, outputFile):
        cipher = AES.new(self.key, AES.MODE_CFB, iv=self.iv, segment_size=128)
        while True:
            block = inputFile.read(self.blockSize)
            if not block:
                break
            encrypted_block = cipher.encrypt(block)
            outputFile.write(encrypted_block)

    def deUpxStream(self, inputFile, outputFile):
        block: bytes = b'1'
        cipher = AES.new(self.key, AES.MODE_CFB, iv=self.iv, segment_size=128)
        header_checked = False
        while block:
            block = inputFile.read(self.blockSize)
            decrypted_block = cipher.decrypt(block)
            if not header_checked:
                if decrypted_block[:4] != b'\x50\x4b\x03\x04':
                    raise ValueError("The decrypted data seems not a zip package, "
                                     "please ensure that the strings or model is correct.")
                header_checked = True
            outputFile.write(decrypted_block)

    def enUpx(self, inputFileName: str, outputFileName: str):
        inputFile = open(inputFileName, mode='rb', buffering=self.blockSize)
        outputFile = open(outputFileName, mode='wb', buffering=self.blockSize)
        self.enUpxStream(inputFile, outputFile)
        inputFile.close()
        outputFile.close()

    def deUpx(self, inputFileName: str, outputFileName: str):
        inputFile = open(inputFileName, mode='rb', buffering=self.blockSize)
        outputFile = open(outputFileName, mode='wb', buffering=self.blockSize)
        self.deUpxStream(inputFile, outputFile)
        inputFile.close()
        outputFile.close()

def findKeyIv(path: str, name: str):
    try:
        with open(path) as file:
            reader = csv.reader(file, delimiter=',')
            line = 0
            for row in reader:
                if line > 0 and (row[0] == name or row[1] == name):
                    return(row)
                line += 1
        return None
    except:
        print(f'"{path}" not found')
        sys.exit()

if __name__ == '__main__':
    import sys
    import os.path

    if len(sys.argv) < 3:
        print('Usage:')
        print('For decrypt: python DeBooxUpdate.py decrypt <device_name> [input.upx [output.zip]]')
        print('For encrypt: python DeBooxUpdate.py encrypt <device_name> [input.zip [output.upx]]')
        sys.exit()

    mode = sys.argv[1].lower()
    if mode not in ['decrypt', 'encrypt']:
        print('Invalid mode. Use "decrypt" or "encrypt" as the first argument.')
        sys.exit()
    device_name = sys.argv[2]

    # 处理输入输出路径
    if mode == 'decrypt':
        input_default = "update.upx"
        output_default = "update.zip"
        input_path = sys.argv[3] if len(sys.argv) >= 4 else input_default
        output_path = sys.argv[4] if len(sys.argv) == 5 else None
        if output_path is None:
            name, ext = os.path.splitext(os.path.basename(input_path))
            output_path = f"{name}.zip" if ext == ".upx" else f"{name}.zip"

    else:  # encrypt
        input_default = "update.zip"
        output_default = "update.upx"
        input_path = sys.argv[3] if len(sys.argv) >= 4 else input_default
        output_path = sys.argv[4] if len(sys.argv) == 5 else None
        if output_path is None:
            name, ext = os.path.splitext(os.path.basename(input_path))
            output_path = f"{name}.upx" if ext == ".zip" else f"{name}.upx"

    # 获取密钥和IV
    csvPath = os.path.join(os.path.split(sys.argv[0])[0], 'BooxKeys.csv')
    row = findKeyIv(csvPath, device_name)
    if row is None:
        print(f'No model named "{device_name}" found')
        sys.exit()

    crypter = DeBooxUpx(row[2], row[3])

    if mode == 'decrypt':
        crypter.deUpx(input_path, output_path)
        print(f"Decrypted to {output_path}")
    else:
        crypter.enUpx(input_path, output_path)
        print(f"Encrypted to {output_path}")
