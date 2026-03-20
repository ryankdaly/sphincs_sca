# SPHINCS+ Side Channel Analysis
## Description
wip
- [sphincs.org](https://sphincs.org/)
- [github.com/sphincs/sphincsplus](https://github.com/sphincs/sphincsplus)
## Requirements
## Python Instructions
1. Download and navigate to the `/sphincs_sca/python/` directory in terminal
2. Install dependencies: `pip install -r requirements.txt`
    - [pycryptodome](https://www.pycryptodome.org) for `rng.py`
3. Run: `python main.py`
    - `--req PATH` Overrride the .req file path (test cases). By default this is `/python/test/PQCsignKAT_128.req`
    - `--rsp PATH` Override the .rsp file path (correct answers). By default this is `/python/test/PQCsignKAT_128.rsp`
    - `--limit n` Run n KATs from the input files instead of all KATs
## Cryptol Instructions
