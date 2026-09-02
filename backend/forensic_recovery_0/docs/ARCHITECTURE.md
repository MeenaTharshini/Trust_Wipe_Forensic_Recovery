# TrustWipe Forensic Architecture

```
+-------------------------------------------------------------+
|                      React Frontend                         |
|                   (Forensics Workbench UI)                  |
+------------------------------+------------------------------+
                               | REST / JSON Polling & Events
                               v
+-------------------------------------------------------------+
|                     Express Backend                         |
|               (backend/src/routes/forensic.js)              |
+------------------------------+------------------------------+
                               | Child Process Spawn (CLI)
                               v
+-------------------------------------------------------------+
|               Python Forensic Recovery Engine               |
|  +-------------------+  +-----------------+  +------------+ |
|  | Evidence (Stream) |  | Carver (Magic)  |  | Chain CoC  | |
|  +-------------------+  +-----------------+  +------------+ |
+-------------------------------------------------------------+
```

## Data Flow
1. User configures case ID & selects target drive or image in React UI.
2. `forensic.js` Express route spawns `cli.py --scan --json`.
3. `Scanner` orchestrates `EvidenceAcquisition`, `FileCarver`, `MetadataExtractor`, and `ChainOfCustody`.
4. Live JSON events stream to Express backend and update React frontend state.
5. Recovered files & immutable audit reports are rendered with cryptographic hash verification.
