"""
This will get a site's ssl sha1 fingerprint and compare it to a known good one
"""

# standard imports
import sys

# imports for the ssl
import ssl
from OpenSSL.crypto import load_certificate, FILETYPE_PEM


# which site?
"""
Make sure you are using a site that you know only has one ev cert.
Google has many different certs. This could give a false positive
Use sites listed on https://www.grc.com/fingerprints.htm
"""
remote_name = "www.yahoo.com"
known_fingerprint = "DC:08:66:CD:F5:15:94:FD:85:CC:F2:49:D5:07:16:45:52:82:8A:D2"  # known fingerprint from https://www.grc.com/fingerprints.htm

def get_cert_fingerprint():

    try:
        full_cert = ssl.get_server_certificate((remote_name, 443))
        cert = load_certificate(FILETYPE_PEM, full_cert)
        sha1_fingerprint = cert.digest("sha1")
        live_fp = sha1_fingerprint.decode('utf-8')  # decode it before returning it
        
    except Exception as e:
            print("I had an issue getting the cert from:", remote_name)
            print(e)
            sys.exit(1)

    print("What's Up Proxy?")
    print("----------------")
    print("")
    print("The cert we are going to fingerprint against is at: " + remote_name)
    print("")
    print("Expected: ", known_fingerprint)
    print("Received: ", live_fp)
    print("")

    if (known_fingerprint != live_fp):
        print("They don't match!")
    else:
        print("It looks like they match")

    print("")
    print("--end--")


## Let's go ##
get_cert_fingerprint()

