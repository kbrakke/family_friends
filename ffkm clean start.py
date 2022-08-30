#ffkm    clean start

import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import random
import functools
import itertools
import hashlib

# 12th Mersenne Prime
# (for this application we want a known prime number as close as
# possible to our security level; e.g.  desired security level of 128
# bits -- too large and all the ciphertext is large; too small and
# security is compromised)
_PRIME = 2**127 - 1
# The 13th Mersenne Prime is 2**521 - 1

_RINT = functools.partial(random.SystemRandom().randint, 0)


def _eval_at(poly, x, prime):
    """Evaluates polynomial (coefficient tuple) at x, used to generate a
    shamir pool in make_random_shares below.
    """
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum


def make_random_shares(secret, minimum, shares, prime=_PRIME):
    """
    Generates a random shamir pool for a given secret, returns share points.
    """
    if minimum > shares:
        raise ValueError("Pool secret would be irrecoverable.")
    poly = [secret] + [_RINT(prime - 1) for i in range(minimum - 1)]
    points = [(i, _eval_at(poly, i, prime)) for i in range(1, shares + 1)]
    # print(points)

    return points


def _extended_gcd(a, b):
    """
    Division in integers modulus p means finding the inverse of the
    denominator modulo p and then multiplying the numerator by this
    inverse (Note: inverse of A is B such that A*B % p == 1). This can
    be computed via the extended Euclidean algorithm
    http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
    """
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y


def _divmod(num, den, p):
    """Compute num / den modulo prime p

    To explain this, the result will be such that:
    den * _divmod(num, den, p) % p == num
    """
    inv, _ = _extended_gcd(den, p)
    return num * inv


def _lagrange_interpolate(x, x_s, y_s, p):
    """
    Find the y-value for the given x, given n (x, y) points;
    k points will define a polynomial of up to kth order.
    """
    k = len(x_s)
    assert k == len(set(x_s)), "points must be distinct"

    def PI(vals):  # upper-case PI -- product of inputs
        accum = 1
        for v in vals:
            accum *= v
        return accum

    nums = []  # avoid inexact division
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
    den = PI(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p) for i in range(k)])
    return (_divmod(num, den, p) + p) % p


def recover_secret(shares, prime=_PRIME):
    """
    Recover the secret from share points
    (points (x,y) on the polynomial).
    """
    if len(shares) < 3:
        raise ValueError("need at least three shares")
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)

#generate list of all 6 choose 3 combinations
arr = list(itertools.combinations(range(1, 7), 3))

#generate a seed and create a key tuples and to seed the key to encrypt and decrypt the wallet
##############type in any random phrase
passphrase = "hash this phrase to start"
# then send phrase to md5()
result = hashlib.md5(passphrase.encode())
passint = result.hexdigest()
#convert to an integer
my_seed = int(passint, 16)
#divide by 100 because algorythm can't solve for numbers too large
adj_seed = int(my_seed/100)
#this is the zero point on the y axis that 3 of the 6 can determine
zero_point = adj_seed
#decide on n choose k.   i did 6 shares and 3 to solve the zero point
shares = make_random_shares(zero_point, minimum=3, shares=6)
#make a dictionary of people(1 through 6) and partial key
share_dict = {}
for p in shares:
    share_dict[p[0]] = p[1]

#print zero point and the 6 partial keys and check the combinations
print("                                                          zero point:  ", zero_point)
print("Shares:")
if shares:
    for share in shares:
        print("  ", share)
#check all combinations
for a in arr:
    print("zero point recovered from 3 tuples minimum subset of shares: ", a, recover_secret(
            [(a[0], share_dict[a[0]]), (a[1], share_dict[a[1]]), (a[2], share_dict[a[2]])]))

def recover_zero_point(partial_key_list):
    b = partial_key_list
    return ("Secret recovered from people ORDER MATTERS: ", b, recover_secret([(b[0][0], b[0][1]), (b[1][0], b[1][1]), (b[2][0], b[2][1])]))
#recover zero point from 3 partial keys ORDER MATTERS!!!!!!!
recovered_zero = recover_zero_point([(3, 144424325175490816130963279003964354075), (4, 20564459533629313024112699365881163014), (5, 37784769956720156689851768385130996662)])
print('recovered zero =   ', recovered_zero[2])

############################################password should be the senders zero point
password = b'1355510807035552233554480135139229696'

#is it ok to make the salt constant???????????????????????????
#salt = os.urandom(16)
salt = b'\xde\xda\xe8\x98\xb8Y\xab\xf6\xbe\xb4\x82\xd9M\x80\x0f\x14'
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)

############### type or paste the secret keys ------     
secret_keys = b'lastpass: some cool phrase  ledger wallet: some other cool phrase ledger pin: 12345 misc currency keys: (monero: 0x f4a2353) safe combo: 2 left 20 three right 21'
token = f.encrypt(secret_keys)
print('token to save', token)

print(f.decrypt(token))
