# -----------------------------------------------------------
# Demonstrates how to extract essential fields from PKCS#10
# certificates with pem extensions
#
# (C) 2021 Nirmal S,
# Released under GNU Public License (GPL)
# -----------------------------------------------------------


from OpenSSL import crypto
from asn1crypto import pem, x509
import OpenSSL.crypto
from os import listdir
from os.path import isfile, join

from OpenSSL.crypto import load_certificate, FILETYPE_PEM

# This function extracts subjectKeyId & authorityKeyId
def extractExtensionId(pem):
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
    authorityKeyId = -1
    subjectKeyId = -1
    # print("***********************")
    for i in range(0, x509.get_extension_count()):
        # print("extension", x509.get_extension(i).get_short_name())
        if('authorityKeyIdentifier' == str(x509.get_extension(i).get_short_name())[2:-1]):
            authorityKeyId = i
        elif('subjectKeyIdentifier' == str(x509.get_extension(i).get_short_name())[2:-1]):
            subjectKeyId = i

    return authorityKeyId, subjectKeyId


# This function verifies if the cert if self-signed or not
def certDetails(pem):
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
    # print("serial number",x509.get_serial_number())
    # print("Issue Name",x509.get_issuer())
    issuer_Details = str(x509.get_issuer())
    subject_Details = str(x509.get_subject())

    # print(issuer_Details)
    # print(subject_Details)
    # print(type(issuer_Details))
    # print("Subject Name", x509.get_subject())
    # print("subject_name_hash",x509.subject_name_hash())

    authorityKeyId, subjectKeyId = extractExtensionId(pem)
    # print(authorityKeyId,subjectKeyId)

    if(authorityKeyId == -1 and subjectKeyId == -1):
        print("Certificate doesn't contain required fields - authorityKeyId & subjectKeyId")
        issuer_subject_check(pem)
    elif(authorityKeyId == -1 and subjectKeyId != -1):
        print("authorityKeyId not found... Further investigation required to examine if this is a self-signed certificate")
        issuer_subject_check(pem)
    elif (authorityKeyId != -1 and subjectKeyId == -1):
        print("subjectKeyId not found")
        issuer_subject_check(pem)

    else:
        authKey = str(x509.get_extension(authorityKeyId).get_data().hex())[-40:]
        subKey = str(x509.get_extension(subjectKeyId).get_data().hex())[-40:]

        if(authKey == subKey):
            print("Self signed certificate detected")
        elif (authKey != subKey):
            print("Not a self signed certificate")

def issuer_subject_check(pem):
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
    # print("serial number", x509.get_serial_number())
    # print("Issue Name", x509.get_issuer())
    issuer_Details = str(x509.get_issuer())
    subject_Details = str(x509.get_subject())

    if(issuer_Details == subject_Details):
        print("Self signed certificate detected based on subject name & issuer name")


mypath = 'Netcraft/'
onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
#print(onlyfiles[0])
#fprint(len(onlyfiles))

#iterate over all Netcraft certs and print all essential fields
for i in range(len(onlyfiles)):
    try:
        print(onlyfiles[i])
        f = open('Netcraft/' + onlyfiles[i], "rb")
        pem = f.read()

        cert = load_certificate(FILETYPE_PEM, pem)

        sha256_fingerprint = cert.digest("sha256")
        print('Certificate Fingerprint sha256')
        # print(sha256_fingerprint)
        sha256 = str(sha256_fingerprint).replace(":", "")
        # print(sha256)
        print(sha256.lower())
        print("Issuer Details")
        print(cert.get_issuer())
        print("Subject Details")
        print(cert.get_subject())
        print("Not Before")
        print(cert.get_notBefore())
        print("Not After")
        print(cert.get_notAfter())
        print("Version in Hex")
        print(cert.get_version())
        print("Key Size")
        print(cert.get_pubkey().bits())
        print("Serial Number")
        print(cert.get_serial_number())
        print("Public Key")
        print(cert.get_pubkey().to_cryptography_key())

        sha1_fingerprint = cert.digest("sha1")
        print('Certificate Fingerprint sha1')
        # print(sha1_fingerprint)
        sha1 = str(sha1_fingerprint).replace(":", "")
        # print(sha1)
        print(sha1.lower())
        print()


    except IOError:
        print("Error: File does not appear to exist.")

    certDetails(pem)
    print('#####################################################################################')
    print('\n')



