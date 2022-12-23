# Rationale

This document contains some rationale around certain decisions or explain potential failure modes in Coraza.

## Why limits should be chosen very carefuly

The only way Coraza can inspect a request body and resolve its legitimity before it reaches upstream is by buffer the body payload, analyse it and then send it to upstream if no threads detected. The main issue with buffering is that if not handled correctly it can become a potential attack door by itself. The buffering process occurs as follows:

1. First, Coraza attempts to buffer the body in memory up to a limit defined by the directive `SecRequestBodyMemoryLimit`, by default Coraza sets `131072`.
2. If the body payload is bigger than the memory limit, Coraza moves off the memory buffering and buffers the body in disk.

Both actions represent a risk when the configuration isn't defensive enough:

1. Buffering in memory, when the limit is high can cause OOM in the system as there is no soft or hard limit on how much memory can be spent on buffering, the OOM will not only affect the attack request but the entire process. It is recommended to keep the default value or lower.
2. Buffering in disk, when not setting the right action can become problematic: an attacker could send huge payloads which will be stored in disk and without proper mitigation (e.g. hard limit on request size or rate limiting) it could fill up the disk, causing degraded functioning in the host. One way to prevent this is to use `SecRequestBodyLimitAction reject` setting, meaning that beyond the request body limit, the request is rejected and no more bytes are writen to disk. Once the request is finished, the buffering file is deleted.
