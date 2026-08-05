# Knowledge Index

Zentrale Wissensbasis. Feste Pfade (nie umbenennen):

- `knowledge/INDEX.md` — dieser Index, Uebersicht aller Wissensdateien
- `knowledge/knowledge.md` — beschreibt das Projekt selbst (Architektur, Komponenten, Konventionen)
- `knowledge/chatlog.md` — Entscheidungen, Aufgaben, Master-Beschluesse
- `knowledge/bugfix.md` — gefundene Bugs + angewendete Fixes
- `knowledge/changelog.md` — was zuletzt am Code geaendert wurde

Semantik: knowledge = das Projekt, changelog = letzte Aenderungen, bugfix = behobene Fehler.

## Regeln

- Nur Master schreibt hier. Subagenten lesen und schlagen Eintraege vor.
- Doku-Pflicht: Jeder Agent liest vor der Arbeit INDEX + knowledge + relevante Datei (changelog/bugfix). Master schreibt nach jeder Aenderung chatlog + changelog (bugfix bei Fehlern).
- Immer anhaengen (append), nie ueberschreiben.
- Format pro Eintrag: `- [YYYY-MM-DD] <Kurztext>`.
- Vor jeder groesseren Aenderung diesen Index + die relevante Datei lesen.
