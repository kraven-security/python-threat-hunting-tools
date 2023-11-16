
from py2exe import freeze 

freeze(
        console=[{'script': 'maltiverse_ip_lookup-v1.py'}],
        options={'py2exe': {'bundle_files': 1, 'compressed': True}},
        zipfile = None
)

