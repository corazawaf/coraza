# Rationale

This document contains some rationale around certain decisions or explain potential failure modes in Coraza.

## Why limits should be chosen very carefully

Coraza can inspect a request body and resolve its legitimacy before it reaches upstream by buffering the body payload, analyzing it, and then sending it upstream if no threads are detected. The main issue with buffering is that it can become a potential attack door by itself if not handled correctly. The buffering process occurs as follows:

1. First, Coraza attempts to buffer the body in memory up to a limit defined by the directive `SecRequestBodyMemoryLimit`, by default Coraza sets `131072`.
2. If the body payload is bigger than the memory limit, Coraza moves off the memory buffering and buffers the body in the disk, up to the limit defined by the directive `SecRequestBodyLimit`. By default Coraza sets this limit to `13107200`.

Both actions represent a risk when the configuration isn't defensive enough:

1. Buffering in memory, when the limit is high can cause OOM in the system as there is no soft or hard limit on how much memory can be spent on buffering, the OOM will not only affect the attack request but the entire process. It is recommended to keep the default value or lower.
2. Buffering in the disk, when not setting the right action can become problematic: an attacker could send huge payloads which will be stored in the disk and without proper mitigation (e.g. hard limit on request size or rate limiting) it could fill up the disk, causing degraded functioning in the host. One way to prevent this is to use `SecRequestBodyLimitAction reject` setting, meaning that beyond the request body limit, the request is rejected and no more bytes are written to the disk. Once the request is finished, the buffered file is deleted.
