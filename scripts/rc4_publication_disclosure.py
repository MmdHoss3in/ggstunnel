"""Preserve validation history when publishing RC4's existing tested archive."""
import sys
from pathlib import Path

path = Path(sys.argv[1])
notice = """## RC4 validation and publication history

Release source is the immutable tag `v0.3.4-rc4`, commit `5fa738b343000c6744a87fdae0c82a5967402f83`. All 46 validation jobs passed in the [existing tagged run](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37821774549/attempts/2). The release job itself failed because its report renderer expected `extended-results/control-path-results.jsonl`, but single-directory artifact uploads flatten that directory. The publication-only repair reads either known layout and retains the exact 64-observation identity/status gate; it does not rebuild or modify the validated binaries. This separate workflow publishes the original checksum-verified archive.

The [first attempt](https://github.com/MmdHoss3in/ggstunnel/actions/runs/37821774549/attempts/1) failed one of 46 amd64 transport observations (compact, payload 1348, reverse, zero-omit accounting). iperf3's receiver interval sum was 163,053,568 bytes, while both its final total and the sum of its 16 final streams were 163,184,640 bytes at 163.179Mbps. One stream differed by one 131,072-byte block. This is consistent with an iperf3 reporting race: [3.16's client samples before stopping receive threads](https://github.com/esnet/iperf/blob/3.16/src/iperf_client_api.c#L693). This is an inference, not proof of the precise interleaving. Only that job and dependent publication were retried once, with unchanged code and criteria; all 46 transport observations then passed. Initial failure logs and locally downloaded evidence remain retained and are not counted as a pass.

This is a prerelease, not Stable or a multiday/DPI guarantee. Longer 30-second 1% loss samples measured 22.125–34.440Mbps; 3% measured 10.562–12.759Mbps. Shorter high-loss rates must not be generalized to sustained 100Mbps. Experimental opaque UDP/raw/DCPI retains four authenticated sender identities, then fails closed and requires restarting both ends. Full generic authenticated rotation, PFS and end-to-end PLPMTUD remain follow-up work.

"""
path.write_text(notice + path.read_text(encoding="utf-8"), encoding="utf-8")
