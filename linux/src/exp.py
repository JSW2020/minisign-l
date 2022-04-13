from base64 import b64decode
from Crypto.Util.number import *

sk = 'EosvqL1DPGwGjI2APf95eSpRmlUXGxtlDCNmHRWJcmM='
pk1 = 'CuTHeYqg8RlHG+4RglvkYgK7eeKlhESV6XwE/03yVIo='
pk2 = 'fAJA+I8c1OFjUqc8F7fxbwc1PlOhdtaEqf4Ma7eY6Fc='
#sk = 'RWRTY0IyBJ+F1znuEvKC+1i5vxqsMSy5KLvcn47KY4ngVyD3GlkAAAACAAAAAAAAAEAAAAAAGsRTR9YF+v4w6OHF1Eb/WCYC5EuuvBNkSo01tPCzU60MUTMu7MFBh2h+j9QR+wRv2UIdiV2OnoqMtkGRnOhbYSVV2CfEv6Q/lTICy/15sdxJxP/LbWr/H16JFwz2ix4NMZ5rLns9KxA='


s = b64decode(sk)
p = bytes_to_long(s)
print(hex(p))

s = b64decode(pk1)
p = bytes_to_long(s)
print(hex(p))

s = b64decode(pk2)
p = bytes_to_long(s)
print(hex(p))
