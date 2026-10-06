# Observer fork candidate retired

Do not merge or publish this observer patch series. It is retained solely as
historical evidence for the superseded contract-7 candidate.

The revised deployment builds unmodified LayerTwo-Labs/bip300301_enforcer at
1753fc0c23863bcb39c681e1cfaea2705613516f. Packaging and compatibility checks live
in bip300-monitor, under deployments/ecash/images and scripts. Observatory
accepts compatible schemas and capabilities and records the source SHA as
provenance; it does not require a patched enforcer.

The old LMDB directory and old OCI artifacts must remain available for paired
rollback. Official upstream starts with a separate enforcer-official-v8 datadir.
No protocol replay engine or private observer RPCs are maintained in this fork.
