# RC5 implementation and validation plan

Baseline: published v0.3.4-rc4, runtime source 5fa738b.
Status: implementation in progress; no new performance or reliability claim.

1. Explicit authenticated generic lifecycle for opaque carriers. Fresh receiver
   challenges bind sender/receiver identities, roles, carrier and version. Keep
   RC4 v1 unchanged; new join codes advertise the incompatible challenge mode.
   Test forged/replayed transitions, >4 peer restarts, loss and key exhaustion.
2. Bounded UDP/raw socket telemetry and accurate generic peer health. Count
   receive/source/format/queue rejection, successful TX and socket errors.
3. Delivery-controller loss/queue review, explicit application-limited epochs,
   bounded low-queue probing and capacity-step repair. Preserve original gates.
4. Transactional transport-change menu retaining TUN addresses, routes, PSK and
   forwarding rules, and preserving stopped/running state; coordinate both peers.
5. Review all changes before cloud execution. No runtime tests/builds locally.
   First run focused cloud security, manager, 30/120-second loss/capacity cases;
   then one complete immutable-tag validation if focused checks succeed.

Full end-to-end PLPMTUD and multicore redesign depend on evidence and are not
assumed implemented. DCPI reachability still needs paired user packet captures.
Do not silently evict replay histories, auto-downgrade formats, weaken thresholds
or claim 95% multiday/DPI guarantees. Publish as candidate until limits justify
Stable. Record each failure and any code repair under a new immutable source.
