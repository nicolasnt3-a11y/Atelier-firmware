# Atelier Firmware

Une interface simple, en français, pour analyser des firmwares avec
[moria](https://github.com/nmatt0/moria) et [mithril](https://github.com/nmatt0/mithril).

- **Moria** ouvre le firmware et en extrait les fichiers.
- **Mithril** inspecte ces fichiers : secrets, logiciels, failles connues (CVE),
  clés faibles, démarrage sécurisé, licences.
- **L'Atelier** enchaîne les deux et présente un rapport lisible par un débutant.
- **L'analyse approfondie** (facultative, activée par défaut) aide à comprendre les firmwares
  que Moria ne sait pas ouvrir (calculateurs automobiles, microcontrôleurs) :
  - carte de la puce et catalogue des messages (`wsl/deep.py`, écrits pour l'Atelier) ;
  - processeur avec [cpu_rec](https://github.com/airbus-seclab/cpu_rec) (Airbus) ;
  - adresse de chargement et table de diagnostic UDS avec [binbloom](https://github.com/quarkslab/binbloom) (Quarkslab) ;
  - deuxième avis et graphique d'entropie avec [binwalk](https://github.com/ReFirmLabs/binwalk) v3 ;
  - traces (numéros de châssis VIN, GPS, téléphones, e-mails, adresses MAC, bases SQLite…) avec
    [bulk_extractor](https://github.com/simsong/bulk_extractor), l'outil de police scientifique informatique ;
  - tables de chiffrement et de contrôle (AES, SHA, RSA, CRC, constantes SHE) avec [yara](https://github.com/VirusTotal/yara),
    les règles de [findcrypt-yara](https://github.com/polymorf/findcrypt-yara) et `wsl/automotive.yar`
    (écrites pour l'Atelier : CRC des profils E2E AUTOSAR en petit- et gros-boutiste, constantes SHE).
- **La rétro-ingénierie** (facultative, à la demande) traduit le code machine en pseudo-code
  et relie chaque message à la fonction qui l'affiche, avec [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
  (NSA) : `wsl/export_ghidra.java` est exécuté par Ghidra après son analyse. Se lance depuis
  l'onglet « Analyse approfondie » d'un rapport, sur une zone de code choisie.

## Utilisation

Double-clique sur **Atelier Firmware** sur le bureau. Une page s'ouvre dans le
navigateur ; glisse un fichier firmware dessus. C'est tout.

L'Atelier s'arrête tout seul quelques minutes après la fermeture de l'onglet.

## Organisation des dossiers

```
C:\Users\<toi>\projets\
├── moria\              ton fork de moria      (jamais modifié par l'Atelier)
├── mithril\            ton fork de mithril    (jamais modifié par l'Atelier)
├── cpu_rec\            copie du dépôt officiel (jamais modifiée)
├── binbloom\           copie du dépôt officiel (jamais modifiée)
├── binwalk\            copie du dépôt officiel (jamais modifiée)
├── bulk_extractor\     copie du dépôt officiel (jamais modifiée)
├── findcrypt-yara\     copie du dépôt officiel (règles yara, jamais modifiées)
└── atelier-firmware\   cette interface
    ├── server.py       le programme qui pilote moria et mithril
    ├── atelier.pyw     le lanceur (utilisé par le raccourci)
    ├── web\            la page affichée dans le navigateur
    └── wsl\
        ├── build.sh          la compilation des outils dans Ubuntu
        ├── deep.py           l'analyse approfondie (niveau 1)
        ├── automotive.yar    règles yara automobiles (CRC E2E, SHE)
        └── export_ghidra.java  l'export de la rétro-ingénierie (niveau 2)

Documents\Atelier Firmware\
├── analyses\           un dossier par analyse (rapports JSON, inventaires SBOM)
└── fichiers-deposes\   les fichiers glissés dans la page
```

Les outils tournent dans **Ubuntu (WSL)** car ils ne fonctionnent que sous Linux.
moria et mithril sont compilés « à côté » de leurs dépôts (`/opt/fwtools/build`) ;
cpu_rec, binbloom, binwalk, bulk_extractor et findcrypt-yara sont d'abord copiés dans
`/opt/fwtools/src`, car leur compilation écrit dans le dossier source. yara vient des
paquets d'Ubuntu (`apt`). Tous sont installés dans `/usr/local/bin`.
Ghidra n'est pas compilé (ce serait trop long) : la version officielle de la NSA est
téléchargée dans `/opt/fwtools/ghidra/` (comme la base de failles), avec Java 21.
Les fichiers extraits sont rangés dans `/root/atelier/` côté Ubuntu.

## Pourquoi les mises à jour ne cassent rien

Chaque dépôt (`moria`, `mithril`) connaît deux adresses :

| nom        | adresse                                   | rôle                          |
|------------|-------------------------------------------|-------------------------------|
| `origin`   | github.com/nicolasnt3-a11y/…              | ton fork                      |
| `upstream` | github.com/nmatt0/…                       | le dépôt officiel de l'auteur |

cpu_rec, binbloom, binwalk, bulk_extractor et findcrypt-yara n'ont pas de fork : `origin` et
`upstream` pointent tous deux vers le dépôt officiel. La mise à jour suit la branche principale
de chaque dépôt officiel (`upstream/HEAD` : `master` ou `main`).

L'Atelier ne modifie aucun fichier des dépôts : il les compile *à côté* et lit
seulement leurs résultats JSON. Le bouton **Outils › Mettre à jour et recompiler**
fait l'équivalent de :

```
git fetch upstream
git merge --ff-only upstream/master   # « avance rapide » : impossible de créer un conflit
```

puis recompile. Si un dépôt a été modifié à la main, l'Atelier refuse de le
mettre à jour plutôt que de risquer d'écraser quelque chose.

Le seul point qui pourrait demander une adaptation : si l'auteur change le
**format JSON** des résultats. Les deux outils indiquent un `schema_version`
(actuellement 1) justement pour signaler ce genre de changement.

## En cas de problème

- La page affiche « L'Atelier ne répond pas » : relance le raccourci.
- Le raccourci a disparu : clic droit sur `creer-raccourci.ps1` › *Exécuter avec PowerShell*.
- Pour voir ce qui se passe : lance `python server.py` dans un terminal depuis ce dossier.
- Journal : `Documents\Atelier Firmware\atelier.log`.
